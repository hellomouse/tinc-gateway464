# Gateway464

Allows IPv4-only clients to access IPv6-only services using network translation while keeping the IPv6 service indirectly (encoded in IP) aware of it's peer's identity. Supports TCP and UDP.

## How it works
When it receives a IPv4 packet from a.b.c.d forwarded to one of the ip:port pairs configured for forwarding it translates the packets into a IPv6 where the source address is:
- The first 48 bits are for the base prefix
- The next 16 bits are (configurable) ip:port-specific
- The next 32 bits are for (configurable) filler
- The next 32 bits encode the source IPv4 address
And the destination address is the one configured for that mapping.
When receiving IPv6 packets, it decodes the source IPv4 address, finds correct ip:port and uses that as destination and source respectively.

