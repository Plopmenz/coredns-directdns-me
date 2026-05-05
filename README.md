# DirectDNS Me

Returns your yggdrasil (ygg0 interface) AAAA address for the specified zones.

The following records will be set:
AAAA in <ipv6-enc>.zone <ipv6> (where <ipv6-enc> is your ygg0 address (<ipv6>) with all `:` replaced by `-`)
CNAME in \_public_dns.<ipv6-enc>.zone <peer> (where <peer> is the \_public_dns NodeInfo of the first peer, if any)

## Example Usage

```
. {
    directdns_me yggdrasil.trustless.cloud
}
```
