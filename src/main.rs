use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use log::*;
use serde::{Deserialize, Serialize};

/// Keep at most this many addresses for each peer
const KEEP_MAX_ADDRESSES: usize = 5;
/// Number of peers to gossip with
const GOSSIP_PEERS: usize = 10;

/// Interval at which to try new addresses when disconnected (1 minute)
const TRY_INTERVAL: Duration = Duration::from_secs(60);
/// Time before a peer is considered dead (5 minutes)
const TIMEOUT: Duration = Duration::from_secs(300);
/// Interval at which to gossip last_seen info
const GOSSIP_INTERVAL: Duration = Duration::from_secs(300);

type Pubkey = String;

#[derive(Deserialize)]
struct Config {
    /// The Wireguard interface name
    interface: Pubkey,
    /// The port to use for gossip inside the Wireguard mesh (must be the same on all nodes)
    gossip_port: u16,
    /// The list of peers we try to connect to
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Deserialize)]
struct Peer {
    /// The peer's Wireguard public key
    pubkey: Pubkey,
    /// The peer's Wireguard address
    address: IpAddr,
    /// An optionnal Wireguard endpoint used to initialize a connection to this peer
    endpoint: Option<SocketAddr>,
}

fn main() -> Result<()> {
    pretty_env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    let config_path = match args.len() {
        0 | 1 => "/etc/wgautomesh.toml",
        2 => &args[1],
        _ => bail!(
            "Usage: {} [path_to_config_file]",
            args.get(0).map(String::as_str).unwrap_or("wgautomesh")
        ),
    };

    let config: Config = {
        let config_str = std::fs::read_to_string(config_path)?;
        toml::from_str(&config_str)?
    };

    Daemon::new(config)?.run()
}

// ============ UTIL =================

fn time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fasthash(data: &[u8]) -> u64 {
    use xxhash_rust::xxh3::Xxh3;

    let mut h = Xxh3::new();
    h.update(data);
    h.digest()
}

fn wg_dump(config: &Config) -> Result<(Pubkey, u16, Vec<(Pubkey, Option<SocketAddr>, u64)>)> {
    let output = Command::new("sudo")
        .args(["wg", "show", &config.interface, "dump"])
        .output()?;
    let mut lines = std::str::from_utf8(&output.stdout)?.split('\n');

    let ourself = lines.next().unwrap().split('\t').collect::<Vec<_>>();
    if ourself.len() < 3 {
        bail!(
            "Unable to fetch wireguard status for interface {}",
            config.interface
        );
    }
    let our_pubkey = ourself[1].to_string();
    let listen_port = ourself[2].parse::<u16>()?;

    let peers = lines
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() < 5 {
                None
            } else {
                Some((
                    fields[0].to_string(),
                    fields[2].parse::<SocketAddr>().ok(),
                    fields[4].parse::<u64>().unwrap(),
                ))
            }
        })
        .collect::<Vec<_>>();

    Ok((our_pubkey, listen_port, peers))
}

// ============ DAEMON CODE =================

struct Daemon {
    config: Config,
    our_pubkey: Pubkey,
    listen_port: u16,
    socket: UdpSocket,
    state: Mutex<State>,
}

struct PeerInfo {
    endpoint: Option<SocketAddr>,
    last_seen: u64,
    gossip_ip: IpAddr,
    gossip_prio: u64,
}

#[derive(Serialize, Deserialize, Debug)]
enum Gossip {
    Announce {
        pubkey: Pubkey,
        endpoints: Vec<(SocketAddr, u64)>,
    },
    Request,
}

impl Daemon {
    fn new(config: Config) -> Result<Self> {
        let (our_pubkey, listen_port, _peers) = wg_dump(&config)?;
        let socket = UdpSocket::bind(SocketAddr::new("0.0.0.0".parse()?, config.gossip_port))?;
        Ok(Daemon {
            config,
            our_pubkey,
            listen_port,
            socket,
            state: Mutex::new(State {
                peers: HashMap::new(),
                gossip: HashMap::new(),
            }),
        })
    }

    fn run(&self) -> Result<()> {
        let request = bincode::serialize(&Gossip::Request)?;
        for peer in self.config.peers.iter() {
            let addr = SocketAddr::new(peer.address, self.config.gossip_port);
            self.socket.send_to(&request, addr)?;
        }

        thread::scope(|s| {
            s.spawn(|| self.wg_loop());
            s.spawn(|| self.recv_loop());
        });
        unreachable!()
    }

    fn wg_loop(&self) -> ! {
        let mut i = 0;
        loop {
            if let Err(e) = self.wg_loop_iter(i) {
                error!("Wg loop error: {}", e);
            }
            i = i + 1;
            std::thread::sleep(TRY_INTERVAL);
        }
    }

    fn wg_loop_iter(&self, i: usize) -> Result<()> {
        let (_, _, wg_peers) = wg_dump(&self.config)?;
        let mut state = self.state.lock().unwrap();

        // 1. Update local peers info of peers
        for (pk, endpoint, last_seen) in wg_peers {
            match state.peers.get_mut(&pk) {
                Some(i) => {
                    i.endpoint = endpoint;
                    i.last_seen = last_seen;
                }
                None => {
                    let gossip_ip = match self.config.peers.iter().find(|x| x.pubkey == pk) {
                        Some(x) => x.address,
                        None => continue,
                    };
                    let gossip_prio = fasthash(format!("{}-{}", self.our_pubkey, pk).as_bytes());
                    state.peers.insert(
                        pk,
                        PeerInfo {
                            endpoint,
                            gossip_prio,
                            gossip_ip,
                            last_seen,
                        },
                    );
                }
            }
        }

        // 2. Send gossip for peers where there is a big update
        let announces = state
            .peers
            .iter()
            .filter_map(|(pk, info)| info.endpoint.map(|ip| (pk, ip, info.last_seen)))
            .filter(|(pk, ip, last_seen)| {
                !state
                    .gossip
                    .get(pk.as_str())
                    .unwrap_or(&vec![])
                    .iter()
                    .any(|(a, t)| a == ip && *last_seen > t + GOSSIP_INTERVAL.as_secs())
            })
            .map(|(pk, ip, last_seen)| (pk.to_string(), vec![(ip, last_seen)]))
            .collect::<Vec<_>>();

        for (pubkey, endpoints) in announces {
            state.handle_announce(self, pubkey, endpoints)?;
        }

        // 3. Try new address for disconnected peers
        let now = time();
        for peer in self.config.peers.iter() {
            // Skip peer if it is in connected state
            if state
                .peers
                .get(&peer.pubkey)
                .map(|x| now < x.last_seen + TIMEOUT.as_secs())
                .unwrap_or(false)
            {
                continue;
            }
            let mut endpoints = state.gossip.get(&peer.pubkey).cloned().unwrap_or_default();
            if endpoints.is_empty() {
                if let Some(endpoint) = peer.endpoint {
                    endpoints.push((endpoint, 0));
                }
            }
            endpoints.sort();
            if !endpoints.is_empty() {
                let endpoint = endpoints[i % endpoints.len()];
                info!("Configure {} with endpoint {}", peer.pubkey, endpoint.0);
                Command::new("sudo")
                    .args([
                        "wg",
                        "set",
                        &self.config.interface,
                        "peer",
                        &peer.pubkey,
                        "endpoint",
                        &endpoint.0.to_string(),
                        "persistent-keepalive",
                        "20",
                        "allowed-ips",
                        &format!("{}/32", peer.address),
                    ])
                    .output()?;
            }
        }

        Ok(())
    }

    fn recv_loop(&self) -> ! {
        loop {
            if let Err(e) = self.recv_loop_iter() {
                error!("Receive loop error: {}", e);
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }

    fn recv_loop_iter(&self) -> Result<()> {
        let (from, gossip) = self.recv_gossip()?;
        let mut state = self.state.lock().unwrap();
        match gossip {
            Gossip::Announce { pubkey, endpoints } => {
                state.handle_announce(self, pubkey, endpoints)?;
            }
            Gossip::Request => {
                for (pubkey, endpoints) in state.gossip.iter() {
                    let packet = bincode::serialize(&Gossip::Announce {
                        pubkey: pubkey.clone(),
                        endpoints: endpoints.clone(),
                    })?;
                    self.socket.send_to(&packet, from)?;
                }
            }
        }
        Ok(())
    }

    fn recv_gossip(&self) -> Result<(SocketAddr, Gossip)> {
        let mut buf = vec![0u8; 1500];
        let (amt, src) = self.socket.recv_from(&mut buf)?;
        if !self.config.peers.iter().any(|x| x.address == src.ip()) {
            bail!("Received message from unexpected peer: {}", src);
        }
        let gossip = bincode::deserialize(&buf[..amt])?;
        debug!("RECV {}\t{:?}", src, gossip);
        Ok((src, gossip))
    }
}

struct State {
    peers: HashMap<Pubkey, PeerInfo>,
    gossip: HashMap<Pubkey, Vec<(SocketAddr, u64)>>,
}

impl State {
    fn send_gossip(&self, daemon: &Daemon, gossip: Gossip) -> Result<()> {
        let packet = bincode::serialize(&gossip)?;

        let now = time();

        let mut peer_vec = self
            .peers
            .iter()
            .filter(|(_, info)| now < info.last_seen + TIMEOUT.as_secs() && info.endpoint.is_some())
            .map(|(_, info)| (info.gossip_ip, info.gossip_prio))
            .collect::<Vec<_>>();
        peer_vec.sort_by_key(|(_, prio)| *prio);

        for (gossip_ip, _) in peer_vec.into_iter().take(GOSSIP_PEERS) {
            let addr = SocketAddr::new(gossip_ip, daemon.config.gossip_port);
            debug!("SEND {}\t{:?}", addr, gossip);
            daemon.socket.send_to(&packet, addr)?;
        }

        Ok(())
    }

    fn handle_announce(
        &mut self,
        daemon: &Daemon,
        pubkey: Pubkey,
        mut endpoints: Vec<(SocketAddr, u64)>,
    ) -> Result<()> {
        let propagate = {
            match self.gossip.get_mut(&pubkey) {
                Some(existing) => {
                    let mut has_new = false;
                    for (new_addr, new_t) in endpoints {
                        if !existing
                            .iter()
                            .any(|(addr, t)| *addr == new_addr && *t >= new_t)
                        {
                            existing.retain(|(addr, _)| *addr != new_addr);
                            existing.push((new_addr, new_t));
                            has_new = true;
                        }
                    }
                    if has_new {
                        existing.sort_by_key(|(_, t)| *t);
                        existing.truncate(KEEP_MAX_ADDRESSES);
                        Some(Gossip::Announce {
                            pubkey,
                            endpoints: existing.clone(),
                        })
                    } else {
                        None
                    }
                }
                None => {
                    endpoints.truncate(KEEP_MAX_ADDRESSES);
                    self.gossip.insert(pubkey.clone(), endpoints.clone());
                    Some(Gossip::Announce { pubkey, endpoints })
                }
            }
        };
        if let Some(propagate) = propagate {
            info!("Propagating announce: {:?}", propagate);
            self.send_gossip(daemon, propagate)?;
        }
        Ok(())
    }
}
