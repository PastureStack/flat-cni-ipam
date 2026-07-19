# Security policy

This migration POC is not yet a production release. Report suspected vulnerabilities privately to the maintainers rather than opening a public issue with exploit details.

The implementation limits metadata responses to 8 MiB, rejects credentials and query data in metadata URLs, permits only the reserved platform link-local metadata addresses and fixed API path, disables redirects and ambient proxies, reads an explicit TLS CA bundle only from `/etc/pasturestack/certs`, bounds lookup time, avoids logging identifiers, and creates optional log files beneath `/var/log/pasturestack` or at the existing `/var/log/pasturestack-cni.log` deployment path with mode `0600`.

Before release, repeat dependency, license, source-tree, race, privileged Linux, and control-plane integration checks against the exact candidate commit.
