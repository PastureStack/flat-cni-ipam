# Security policy

This migration POC is not yet a production release. Report suspected vulnerabilities privately to the maintainers rather than opening a public issue with exploit details.

The implementation limits metadata responses to 8 MiB, rejects credentials and query data in metadata URLs, restricts redirects to the configured host, supports an explicit TLS CA bundle, bounds lookup time, avoids logging identifiers, and creates optional log files with mode `0600`.

Before release, repeat dependency, license, source-tree, race, privileged Linux, and control-plane integration checks against the exact candidate commit.
