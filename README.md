# wgautomesh

`wgautomesh` is a simple utility to help configure a full-mesh wireguard network.
It does not assume that all nodes have a publicly reachable address.  It uses a
gossip protocol to broadcast the endpoint addresses nodes use to talk to one
another. This way, even if nodes A and B are not able to communicate directly
initially (both behind NAT), if they can both communicate with node C then they
will indirectly be able to know each other's NAT-ed address and port. They will
then try to connect to one another using those addresses, which should allow
NAT hole punching.

Features:

- does not assume all nodes are publicly reachable
- configuration very similar to `wg-quick`: each node needs a list of the credentials of all other nodes in the mesh
- ultra simple encrypted gossip protocol over UDP (bincode encoding + xsalsa20poly1305 symmetric encryption)
- automatic discovery of nodes in a same LAN using UDP broadcast (if enabled, nodes will prefer connecting to one another using their LAN IP addresses when available)
- can automatically open ports in your router using IGD/UPnP
- saves to disk known addresses of peers so that they can be reused on restart (usefull if all addresses have changed and the ones in the config file are no longer relevant)

Remarks/limitations:

- `wgautomesh` does not create a wireguard interface, it assumes it exists and merely configures the peers attached to it
- `wgautomesh` only tries to establish connectivity to the peers specified in its config file,
it does not provide facilities for dynamically adding more peers like many wireguard configuration tools do.

`wgautomesh` was built for Deuxfleurs to integrate with our automated NixOS-based configuration management system.
A preliminary NixOS module for `wgautomesh` can be found [here](https://git.deuxfleurs.fr/Deuxfleurs/nixcfg/src/branch/wgautomesh/nix/wgautomesh.nix)

### Sample configuration file

```toml
interface = "wg0"
gossip_port = 1666
lan_discovery = true
gossip_secret_file = "/var/lib/wgautomesh/gossip_secret"
persist_file = "/var/lib/wgautomesh/state"
upnp_forward_external_port = 33723

[[peers]]
pubkey = "7Nm7pMmyS7Nts1MB+loyD8u84ODxHPTkDu+uqQR6yDk="
address = "10.14.1.2"
endpoint = "77.207.15.215:33722"

[[peers]]
pubkey = "lABn/axzD1jkFulX8c+K3B3CbKXORlIMDDoe8sQVxhs="
address = "10.14.1.3"
endpoint = "77.207.15.215:33723"

[[peers]]
pubkey = "XLOYoMXF+PO4jcgfSVAk+thh4VmWx0wzWnb0xs08G1s="
address = "10.14.4.1"
endpoint = "bitfrost.fiber.shirokumo.net:33734"

[[peers]]
pubkey = "smBQYUS60JDkNoqkTT7TgbpqFiM43005fcrT6472llI="
address = "10.14.2.33"
endpoint = "82.64.238.84:33733"

[[peers]]
pubkey = "m9rLf+233X1VColmeVrM/xfDGro5W6Gk5N0zqcf32WY="
address = "10.14.3.1"
```
