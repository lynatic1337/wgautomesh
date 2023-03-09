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
- `wgautomesh` does not create a wireguard interface, it assumes it exists and merely configures the peers attached to it
- ultra simple encrypted gossip protocol over UDP (bincode encoding + xsalsa20poly1305 symmetric encryption)
- automatic discovery of nodes in a same LAN using UDP broadcast (if enabled, nodes will prefer connecting to one another using their LAN IP addresses when available)
- can automatically open ports in your router using IGD/UPnP

**`wgautomesh` only tries to establish connectivity to the peers specified in its config file**,
it does not provide facilities for dynamically adding more peers like many wireguard configuration tools do.
