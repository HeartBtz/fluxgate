# Security Policy

## Supported versions

Security fixes are provided for the latest release. Upgrade to the latest
release before reporting an issue that may already be fixed.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/HeartBtz/fluxgate/security/advisories/new)
and include affected versions, impact, reproduction steps, and any suggested
mitigation. Avoid including real credentials, personal data, or third-party
systems in the report.

You should receive an acknowledgment after the report is reviewed. Please allow
time for a fix and coordinated disclosure before publishing details.

## Deployment responsibility

FluxGate must be deployed behind HTTPS for non-local use. Operators are
responsible for access control, secret management, encrypted disks or buckets,
backups, restore testing, reverse-proxy limits, and keeping dependencies and the
container host updated. See the security limitations in the README.
