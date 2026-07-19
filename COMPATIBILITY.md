# Compatibility contract

The POC preserves the externally observable flat-network IPAM contract while removing obsolete build and vendoring machinery.

## Inputs

- CNI network fields: `name`, `cniVersion`, `bridge`, `bridgeSubnet`, and `ipam`;
- IPAM fields: `type`, `routes`, `subnetPrefixSize`, `metadataURL`, `metadataAddress`, `lookupTimeout`, and `pollInterval`;
- CNI arguments: `IPAddress` and `PlatformContainerUUID`;
- runtime overrides: `PLATFORM_METADATA_URL`, `PLATFORM_METADATA_ADDRESS`, and `PLATFORM_CA_ROOT`.

## Output and behavior

- `ADD` returns one IPv4 allocation plus the configured routes and one host route to the metadata address;
- an address-supplied CIDR takes precedence over `subnetPrefixSize`, which takes precedence over the prefix from `bridgeSubnet`;
- metadata lookup is skipped when `IPAddress` is supplied;
- `CHECK` validates address resolution and gateway selection;
- `DEL` is idempotent because this plugin keeps no lease state.

Privileged Linux routing, network-namespace integration, IPv6 support, and real control-plane metadata remain separate acceptance gates.
