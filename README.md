# Flat CNI IPAM

`flat-cni-ipam` is a Linux CNI IPAM plugin for assigning a control-plane-provided IPv4 address on a flat network and returning the route required to reach the platform metadata endpoint.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/rancher-flat-ipam`](https://github.com/rancher/rancher-flat-ipam). This GitHub fork retains the upstream Git history, authorship, dates, and license notices unchanged; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## POC scope

- CNI versions 0.1.0 through 1.1.0;
- an IPv4 address supplied through `CNI_ARGS`, with metadata lookup as a fallback;
- a prefix supplied by the address, `subnetPrefixSize`, or `bridgeSubnet`;
- deterministic bridge gateway selection within `bridgeSubnet`;
- a configurable IPv4 metadata route, metadata endpoint, lookup timeout, and polling interval;
- an 8 MiB metadata response limit and optional HTTPS CA bundle.

The plugin has no user interface or language catalog, so localization is not applicable. IPv6 and privileged network-namespace behavior are outside this POC and remain explicit follow-up gates.

## Build and test

```sh
go test ./...
go vet ./...
go mod verify
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/flat-cni-ipam .
```

## Configuration

```json
{
  "cniVersion": "1.1.0",
  "name": "pasture-flat-network",
  "bridge": "pasture0",
  "bridgeSubnet": "10.42.0.1/16",
  "ipam": {
    "type": "flat-cni-ipam",
    "metadataURL": "http://metadata/2015-12-19",
    "metadataAddress": "169.254.169.250",
    "lookupTimeout": "2m",
    "pollInterval": "500ms"
  }
}
```

`CNI_ARGS` may supply `IPAddress` and `PlatformContainerUUID`. `PLATFORM_METADATA_URL`, `PLATFORM_METADATA_ADDRESS`, and `PLATFORM_CA_ROOT` override their corresponding runtime settings.

## License and provenance

The root Apache-2.0 license remains unchanged. Existing history and attribution are retained; see [ORIGIN.md](ORIGIN.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [LICENSE](LICENSE).
