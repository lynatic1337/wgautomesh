use log::*;
use std::net::IpAddr;
use futures::stream::{StreamExt};
use rupnp::{Device, Service};
use rupnp::ssdp::{SearchTarget, URN};
use std::str::FromStr;
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result, Error};
const IGD_LEASE_DURATION: Duration = Duration::from_secs(300);
const WAN_IPV6_FIREWALL_CONTROL: URN = URN::service("schemas-upnp-org", "WANIPv6FirewallControl", 1);
const WAN_IP_CONNECTION: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
pub async fn igd_loop_iter(listen_port:u16, external_port: u16, use_ipv6: bool) -> Result<()> {
    let lease_duration: u64 = IGD_LEASE_DURATION.as_secs();
    //find gateway compatible with publishing the port for required IP version
    let gateway = find_gateway(use_ipv6).await?;
    let gateway_ip: IpAddr = IpAddr::from_str(gateway.url().host().unwrap())?;

    //find corresponding interface local IP to forward in gateway
    let local_ip = select_local_ip_for_gateway(gateway_ip,use_ipv6)?;
    println!("local_ip: {}", local_ip);
    debug!(
        "Found gateway: {:?} at IP {}, making announce",
        gateway.friendly_name(),
        gateway.url().host().unwrap()
    );

    if use_ipv6 {
        create_ipv6_firewall_pinhole(
            gateway,
            &local_ip,
            listen_port,
            external_port,
            &lease_duration,
        )
            .await
    } else {
        create_ipv4_port_mapping(
            gateway,
            &local_ip,
            listen_port,
            external_port,
            &lease_duration,
        )
            .await
    }
}
/// Create a port mapping to forward a given Port for a given internal IPv4
async fn create_ipv4_port_mapping(
    gateway: Device,
    internal_ip: &IpAddr,
    listen_port: u16,
    external_port: u16,
    lease_duration: &u64,
) -> Result<()> {
    let wan_ip_con_service = gateway
        .find_service(&WAN_IP_CONNECTION)
        .expect("Gateway passed doesn't offer the required service to create IPv4 port mapping");
    let arguments = format!(
        "<NewRemoteHost/>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
<NewInternalPort>{listen_port}</NewInternalPort>
<NewInternalClient>{internal_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Wireguard via wgautomesh</NewPortMappingDescription>
<NewLeaseDuration>{lease_duration}</NewLeaseDuration>"
    );
    debug!(
        "Adding port mapping for internal IP {} on internal port {}, external port {}",
        internal_ip, listen_port, external_port,
    );
    let result = wan_ip_con_service
        .action(gateway.url(), "AddPortMapping", &arguments)
        .await;
    if result.is_ok() {
        Ok(())
    } else {
        bail!(
            "Error trying to add IPv4 port mapping: {}.\
            Note: Have you checked whether your router allows this device to create (IPv4) port mappings?",
            result.err().unwrap()
        );
    }
}
/// Create a pinhole for a given IPv6 address on a given port
async fn create_ipv6_firewall_pinhole(gateway: Device,
                                      ip: &IpAddr,
                                      listen_port: u16,
                                      external_port: u16,
                                      lease_duration: &u64,
) -> Result<()> {
    let wan_ip6_fw_con = gateway
        .find_service(&WAN_IPV6_FIREWALL_CONTROL)
        .expect("Gateway passed doesn't offer the required service to create IPv6 pinholes");
    let (firewall_enabled, can_create_inbound_pinhole) =
        get_firewall_status(&gateway, &wan_ip6_fw_con).await;
    if !firewall_enabled {
        debug!("Gateway firewall is not enabled, incoming connections should be allowed as-is on all ports");
        return Ok(());
    } else if !can_create_inbound_pinhole {
        bail!("Gateway said creating inbound IPv6 pinholes isn't allowed")
    }
    let arguments = format!(
        "<RemoteHost/>
<RemotePort>{external_port}</RemotePort>
<Protocol>17</Protocol>
<InternalPort>{listen_port}</InternalPort>
<InternalClient>{ip}</InternalClient>
<LeaseTime>{lease_duration}</LeaseTime>"
    );
    debug!(
        "Opening firewall pinhole for IP {} on internal port {}, external port {}",
        ip, listen_port, external_port,
    );
    let result = wan_ip6_fw_con
        .action(gateway.url(), "AddPinhole", &arguments)
        .await;
    if result.is_ok() {
        Ok(())
    } else {
        bail!(
            "Error trying to open IPv6 pinhole: {}\
            Note: Have you checked whether your router allows this device to create (IPv6) pinholes?",
            result.err().unwrap()
        );
    }
}
/// Asks the Gateway for the IPv6 Firewall status (whether the firewall is enabled AND whether devices in this network are allowed to create IPv6 pinholes per policy).
/// Note: This only works on IGDv2 supporting firewalls (-> any firewall that can do IPv6)
async fn get_firewall_status(gateway: &Device, igd_service: &Service) -> (bool, bool) {
    let firewall_status_response = igd_service
        .action(gateway.url(), "GetFirewallStatus", "")
        .await
        .unwrap();
    let firewall_enabled: bool =
        (u32::from_str(firewall_status_response.get("FirewallEnabled").unwrap()).unwrap()) != 0;
    let can_create_inbound_pinhole: bool = u32::from_str(
        firewall_status_response
            .get("InboundPinholeAllowed")
            .unwrap(),
    )
        .unwrap()
        != 0;
    (firewall_enabled, can_create_inbound_pinhole)
}
/// Find a Gateway compatible with either IPv4 (supports WANIPConnection) or IPv6 (supports WANIPv6FirewallControl)
async fn find_gateway(ipv6_required: bool) -> Result<Device, Error> {
    let search_urn: URN = if ipv6_required {
        WAN_IPV6_FIREWALL_CONTROL
    } else {
        WAN_IP_CONNECTION
    };

    let discovered_devices = rupnp::discover(
        &SearchTarget::URN(search_urn.clone()),
        Duration::from_secs(3),
    )
        .await?
        .filter_map(|result| async {
            match result {
                Ok(device) => Some(device),
                Err(_) => None,
            }
        });
    futures::pin_mut!(discovered_devices);
    discovered_devices.next().await.ok_or_else(||anyhow!("Couldn't find any gateways supporting {}. Is port 1900 open for incoming connections from local networks?", search_urn.typ()))
}
/// Returns a list of IPs assigned to interfaces that are in the same subnet as a given IP
fn interface_ips_in_same_subnet_as(ip_to_match: IpAddr) -> Result<Vec<IpAddr>, Error> {
    let interfaces = pnet::datalink::interfaces();
    let ipnets = interfaces
        .iter()
        .filter_map(|interface| {
            if interface
                .ips
                .iter()
                .any(|ipnetwork| ipnetwork.contains(ip_to_match))
            {
                Some(interface.ips.clone())
            } else {
                None
            }
        })
        .next()
        .context("Couldn't find any local IPs within the same network as given IP")?;
    let ips = ipnets.iter().map(|ip| ip.ip()).collect();
    Ok(ips)
}
/// Selects the local IP we tell the Gateway to port forward to (/pinhole) later on
/// Note: As soon as this[https://github.com/jakobhellermann/ssdp-client/issues/11] is fixed and the dependency is upgraded in rupnp, we can simplify it
fn select_local_ip_for_gateway(gateway: IpAddr, output_ipv6: bool) -> Result<IpAddr, Error> {
    //get IPs in same subnet as Gateway
    let ips = interface_ips_in_same_subnet_as(gateway)?;
    //removes IPv6 that are not globally routable as pinholing those would be pointless
    let v6_cleaned_up = ips
        .iter()
        .filter(|ip| ip.is_ipv4() || (ip.is_global() && ip.is_ipv6()));
    //filters IPs to match the ipv6 output criteria
    let mut viable_ips = v6_cleaned_up.filter(|ip| ip.is_ipv6() == output_ipv6);
    //return the first IP
    viable_ips
        .next()
        .copied()
        .ok_or_else(|| anyhow!("Couldn't find an IP address"))
}