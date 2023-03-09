use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use log::*;
use serde::{Deserialize, Serialize};

/// Keep at most this many addresses for each peer
const KEEP_MAX_ADDRESSES: usize = 5;
/// Number of peers to gossip with
const GOSSIP_PEERS: usize = 10;

/// Interval at which to try new addresses when disconnected
const TRY_INTERVAL: Duration = Duration::from_secs(30);
/// Time before a peer is considered dead (5 minutes)
const TIMEOUT: Duration = Duration::from_secs(300);
/// Interval at which to gossip last_seen info
const GOSSIP_INTERVAL: Duration = Duration::from_secs(300);

const LAN_BROADCAST_INTERVAL: Duration = Duration::from_secs(60);

const IGD_INTERVAL: Duration = Duration::from_secs(60);
const IGD_LEASE_DURATION: Duration = Duration::from_secs(300);

type Pubkey = String;

#[derive(Deserialize)]
struct Config {
    /// The Wireguard interface name
    interface: Pubkey,
    /// The port to use for gossip inside the Wireguard mesh (must be the same on all nodes)
    gossip_port: u16,
    /// The secret to use to authenticate nodes between them
    gossip_secret: Option<String>,
    gossip_secret_file: Option<String>,

    /// Enable LAN discovery
    #[serde(default)]
    lan_discovery: bool,

    /// Forward an external port to Wiregard using UPnP IGD
    upnp_forward_external_port: Option<u16>,

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
    endpoint: Option<String>,
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

    let mut config: Config = {
        let config_str = std::fs::read_to_string(config_path)?;
        toml::from_str(&config_str)?
    };

    if let Some(f) = &config.gossip_secret_file {
        if config.gossip_secret.is_some() {
            bail!("both gossip_secret and gossip_secret_file are given in config file");
        }
        config.gossip_secret = Some(std::fs::read_to_string(f)?);
    }

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

fn kdf(secret: &str) -> xsalsa20poly1305::Key {
    let hash = blake3::hash(format!("wgautomesh: {}", secret).as_bytes());
    hash.as_bytes().clone().into()
}

fn wg_dump(config: &Config) -> Result<(Pubkey, u16, Vec<(Pubkey, Option<SocketAddr>, u64)>)> {
    let output = Command::new("wg")
        .args(["show", &config.interface, "dump"])
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
    gossip_key: xsalsa20poly1305::Key,
    our_pubkey: Pubkey,
    listen_port: u16,
    socket: UdpSocket,
    state: Mutex<State>,
}

struct PeerInfo {
    // Info known from config
    gossip_ip: IpAddr,
    gossip_prio: u64,
    // Info retrieved from wireguard
    endpoint: Option<SocketAddr>,
    last_seen: u64,
    // Info received by LAN broadcast
    lan_endpoint: Option<(SocketAddr, u64)>,
}

#[derive(Serialize, Deserialize, Debug)]
enum Gossip {
    Announce {
        pubkey: Pubkey,
        endpoints: Vec<(SocketAddr, u64)>,
    },
    Request,
    LanBroadcast {
        pubkey: Pubkey,
        listen_port: u16,
    },
}

impl Daemon {
    fn new(config: Config) -> Result<Self> {
        let gossip_key = kdf(config.gossip_secret.as_deref().unwrap_or_default());

        let (our_pubkey, listen_port, _peers) = wg_dump(&config)?;
        let socket = UdpSocket::bind(SocketAddr::new("0.0.0.0".parse()?, config.gossip_port))?;
        socket.set_broadcast(true)?;
        Ok(Daemon {
            config,
            gossip_key,
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
        if let Err(e) = self.state.lock().unwrap().setup_wg_peers(self, 0) {
            error!("Error initializing wireguard peers: {}", e);
        }

        let request = self.make_packet(&Gossip::Request)?;
        for peer in self.config.peers.iter() {
            let addr = SocketAddr::new(peer.address, self.config.gossip_port);
            if let Err(e) = self.socket.send_to(&request, addr) {
                error!("Error sending initial request to {}: {}", addr, e);
            }
        }

        thread::scope(|s| {
            s.spawn(|| self.wg_loop());
            s.spawn(|| self.recv_loop());
            s.spawn(|| self.lan_broadcast_loop());
            s.spawn(|| self.igd_loop());
        });
        unreachable!()
    }

    fn wg_loop(&self) -> ! {
        let mut i = 0;
        loop {
            if let Err(e) = self.wg_loop_iter(i) {
                error!("Wireguard configuration loop error: {}", e);
            }
            i = i + 1;
            std::thread::sleep(TRY_INTERVAL);
        }
    }

    fn wg_loop_iter(&self, i: usize) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        // 1. Update local peers info of peers
        state.read_wg_peers(self)?;

        // 2. Send gossip for peers where there is a big update
        let announces = state
            .peers
            .iter()
            .filter_map(|(pk, info)| info.endpoint.map(|ip| (pk, ip, info.last_seen)))
            .filter(|(pk, ip, last_seen)| {
                state
                    .gossip
                    .get(pk.as_str())
                    .unwrap_or(&vec![])
                    .iter()
                    .all(|(a, t)| a != ip || *last_seen > t + GOSSIP_INTERVAL.as_secs())
            })
            .map(|(pk, ip, last_seen)| (pk.to_string(), vec![(ip, last_seen)]))
            .collect::<Vec<_>>();

        for (pubkey, endpoints) in announces {
            state.handle_announce(self, pubkey, endpoints)?;
        }

        // 3. Try new address for disconnected peers
        state.setup_wg_peers(self, i)?;

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
                    let packet = self.make_packet(&Gossip::Announce {
                        pubkey: pubkey.clone(),
                        endpoints: endpoints.clone(),
                    })?;
                    self.socket.send_to(&packet, from)?;
                }
            }
            Gossip::LanBroadcast {
                pubkey,
                listen_port,
            } => {
                if self.config.lan_discovery {
                    if let Some(peer) = state.peers.get_mut(&pubkey) {
                        let addr = SocketAddr::new(from.ip(), listen_port);
                        peer.lan_endpoint = Some((addr, time()));
                    }
                }
            }
        }
        Ok(())
    }

    fn recv_gossip(&self) -> Result<(SocketAddr, Gossip)> {
        use xsalsa20poly1305::{
            aead::{Aead, KeyInit},
            XSalsa20Poly1305, NONCE_SIZE,
        };

        let mut buf = vec![0u8; 1500];
        let (amt, src) = self.socket.recv_from(&mut buf)?;

        if amt < NONCE_SIZE {
            bail!("invalid packet");
        }

        let cipher = XSalsa20Poly1305::new(&self.gossip_key);
        let plaintext = cipher
            .decrypt(buf[..NONCE_SIZE].try_into().unwrap(), &buf[NONCE_SIZE..amt])
            .map_err(|e| anyhow!("decrypt error: {}", e))?;

        let gossip = bincode::deserialize(&plaintext)?;
        trace!("RECV {}\t{:?}", src, gossip);
        Ok((src, gossip))
    }

    fn lan_broadcast_loop(&self) {
        if self.config.lan_discovery {
            loop {
                if let Err(e) = self.lan_broadcast_iter() {
                    error!("LAN broadcast loop error: {}", e);
                }
                std::thread::sleep(LAN_BROADCAST_INTERVAL);
            }
        }
    }

    fn lan_broadcast_iter(&self) -> Result<()> {
        let packet = self.make_packet(&Gossip::LanBroadcast {
            pubkey: self.our_pubkey.clone(),
            listen_port: self.listen_port,
        })?;
        let addr = SocketAddr::new("255.255.255.255".parse().unwrap(), self.config.gossip_port);
        self.socket.send_to(&packet, addr)?;
        Ok(())
    }

    fn igd_loop(&self) {
        if let Some(external_port) = self.config.upnp_forward_external_port {
            loop {
                if let Err(e) = self.igd_loop_iter(external_port) {
                    error!("IGD loop error: {}", e);
                }
                std::thread::sleep(IGD_INTERVAL);
            }
        }
    }

    fn igd_loop_iter(&self, external_port: u16) -> Result<()> {
        let gateway = igd::search_gateway(Default::default())?;

        let gwa = gateway.addr.ip().octets();
        let cmplen = match gwa {
            [192, 168, _, _] => 3,
            [10, _, _, _] => 2,
            _ => bail!(
                "Gateway IP does not appear to be in a local network ({})",
                gateway.addr.ip()
            ),
        };
        let private_ip = get_if_addrs::get_if_addrs()?
            .into_iter()
            .map(|i| i.addr.ip())
            .filter_map(|a| match a {
                std::net::IpAddr::V4(a4) if a4.octets()[..cmplen] == gwa[..cmplen] => Some(a4),
                _ => None,
            })
            .next()
            .ok_or(anyhow!("No interface has an IP on same subnet as gateway"))?;
        info!(
            "IGD: gateway is {}, private IP is {}, making announce",
            gateway.addr, private_ip
        );

        gateway.add_port(
            igd::PortMappingProtocol::UDP,
            external_port,
            SocketAddrV4::new(private_ip, self.listen_port),
            IGD_LEASE_DURATION.as_secs() as u32,
            "Wireguard via wgautomesh",
        )?;

        Ok(())
    }

    fn make_packet(&self, gossip: &Gossip) -> Result<Vec<u8>> {
        use xsalsa20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            XSalsa20Poly1305,
        };

        let plaintext = bincode::serialize(&gossip)?;

        let cipher = XSalsa20Poly1305::new(&self.gossip_key);
        let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, &plaintext[..])
            .map_err(|e| anyhow!("encrypt error: {}", e))?;

        Ok([&nonce[..], &ciphertext[..]].concat())
    }
}

struct State {
    peers: HashMap<Pubkey, PeerInfo>,
    gossip: HashMap<Pubkey, Vec<(SocketAddr, u64)>>,
}

impl State {
    fn send_gossip(&self, daemon: &Daemon, gossip: Gossip) -> Result<()> {
        let packet = daemon.make_packet(&gossip)?;

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
            trace!("SEND {}\t{:?}", addr, gossip);
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
                        if existing
                            .iter()
                            .all(|(addr, t)| *addr != new_addr || *t < new_t)
                        {
                            existing.retain(|(addr, _)| *addr != new_addr);
                            existing.push((new_addr, new_t));
                            has_new = true;
                        }
                    }
                    if has_new {
                        existing.sort_by_key(|(_, t)| -(*t as i64));
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
                    endpoints.sort_by_key(|(_, t)| -(*t as i64));
                    endpoints.truncate(KEEP_MAX_ADDRESSES);
                    self.gossip.insert(pubkey.clone(), endpoints.clone());
                    Some(Gossip::Announce { pubkey, endpoints })
                }
            }
        };
        if let Some(propagate) = propagate {
            debug!("Propagating announce: {:?}", propagate);
            self.send_gossip(daemon, propagate)?;
        }
        Ok(())
    }

    fn read_wg_peers(&mut self, daemon: &Daemon) -> Result<()> {
        let (_, _, wg_peers) = wg_dump(&daemon.config)?;
        for (pk, endpoint, last_seen) in wg_peers {
            match self.peers.get_mut(&pk) {
                Some(i) => {
                    i.endpoint = endpoint;
                    i.last_seen = last_seen;
                }
                None => {
                    let gossip_ip = match daemon.config.peers.iter().find(|x| x.pubkey == pk) {
                        Some(x) => x.address,
                        None => continue,
                    };
                    let gossip_prio = fasthash(format!("{}-{}", daemon.our_pubkey, pk).as_bytes());
                    self.peers.insert(
                        pk,
                        PeerInfo {
                            endpoint,
                            lan_endpoint: None,
                            gossip_prio,
                            gossip_ip,
                            last_seen,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    fn setup_wg_peers(&mut self, daemon: &Daemon, i: usize) -> Result<()> {
        let now = time();
        for peer_cfg in daemon.config.peers.iter() {
            // Skip ourself
            if peer_cfg.pubkey == daemon.our_pubkey {
                continue;
            }

            if let Some(peer) = self.peers.get_mut(&peer_cfg.pubkey) {
                // remove LAN endpoint info if it is obsolete
                if matches!(peer.lan_endpoint, Some((_, t)) if now > t + TIMEOUT.as_secs()) {
                    peer.lan_endpoint = None;
                }

                // make sure we aren't skipping this peer (see below) if we can switch to LAN
                // endpoint instead of currently connected one
                let bad_endpoint = match (&peer.lan_endpoint, &peer.endpoint) {
                    (Some((addr1, _)), Some(addr2)) => addr1 != addr2,
                    _ => false,
                };

                // if peer is connected and endpoint is the correct one,
                // set higher keepalive and then skip reconfiguring it
                if !bad_endpoint && now < peer.last_seen + TIMEOUT.as_secs() {
                    Command::new("wg")
                        .args([
                            "set",
                            &daemon.config.interface,
                            "peer",
                            &peer_cfg.pubkey,
                            "persistent-keepalive",
                            "30",
                        ])
                        .output()?;
                    continue;
                }
            }

            // For disconnected peers, cycle through the endpoint addresses that we know of
            let lan_endpoint = self
                .peers
                .get(&peer_cfg.pubkey)
                .and_then(|peer| peer.lan_endpoint);

            let endpoints = match lan_endpoint {
                Some(endpoint) => vec![endpoint],
                None => {
                    let mut endpoints = self
                        .gossip
                        .get(&peer_cfg.pubkey)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(endpoint) = &peer_cfg.endpoint {
                        match endpoint.to_socket_addrs() {
                            Err(e) => error!("Could not resolve DNS for {}: {}", endpoint, e),
                            Ok(iter) => {
                                for addr in iter {
                                    endpoints.push((addr, 0));
                                }
                            }
                        }
                    }
                    endpoints.sort();
                    endpoints
                }
            };

            if !endpoints.is_empty() {
                let endpoint = endpoints[i % endpoints.len()];
                info!("Configure {} with endpoint {}", peer_cfg.pubkey, endpoint.0);
                Command::new("wg")
                    .args([
                        "set",
                        &daemon.config.interface,
                        "peer",
                        &peer_cfg.pubkey,
                        "endpoint",
                        &endpoint.0.to_string(),
                        "persistent-keepalive",
                        "10",
                        "allowed-ips",
                        &format!("{}/32", peer_cfg.address),
                    ])
                    .output()?;
            } else {
                info!("Configure {} with no known endpoint", peer_cfg.pubkey);
                Command::new("wg")
                    .args([
                        "set",
                        &daemon.config.interface,
                        "peer",
                        &peer_cfg.pubkey,
                        "allowed-ips",
                        &format!("{}/32", peer_cfg.address),
                    ])
                    .output()?;
            }
        }

        Ok(())
    }
}
