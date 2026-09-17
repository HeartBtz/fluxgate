# Relay production contract

GitLab project `dev/fluxgate` is the authoritative repository. Merge requests
run `go-test` and `go-vet` only from a real `merge_request_event`. Exact
`vMAJOR.MINOR.PATCH` tags run those jobs plus `release-policy` and
`build-release`; the release artifact embeds the tag without its leading `v`.

## Production blocker

`deploy-production` is intentionally absent. The existing CT110 forced receiver
cannot deploy artifacts from this repository:

- it fetches `git@git.hbtz.fr:homelab/fluxgate.git`, not `dev/fluxgate`;
- it requires the embedded module `git.hbtz.fr/HeartBtz/fluxgate`, while this
  public project declares `github.com/HeartBtz/fluxgate`;
- GitLab project `dev/fluxgate` does not currently protect the `v*` tag pattern.

Changing this repository's public module identity would break its documented
Go import path and would still not fix the receiver's repository mismatch. The
receiver must instead fetch `dev/fluxgate`, accept the declared module, receive
the repository client's checksum-verified artifact, and retain its bounded
forced-command protocol. Relay then verifies that `/health` returns the exact
release version. CT110 must be changed and reviewed separately; this repository
does not attempt to modify it.

After that receiver change, add a protected, manual, tag-only
`deploy-production` job using `scripts/deploy-production.sh`. Configure its
environment as `production`, serialize it with a FluxGate-specific
`resource_group`, and protect `v*` so only Relay's release identity can create
release tags or play the job.

The eventual Relay deployment configuration is:

```json
{
  "provider": "gitlab",
  "release": "semver_tag",
  "productionJob": "deploy-production",
  "productionEnvironment": "production",
  "requiredJobs": ["go-test", "go-vet", "release-policy", "build-release"],
  "healthUrl": "http://192.168.1.110:8080/health",
  "health": {
    "statusField": "status",
    "statusValue": "healthy",
    "versionField": "version"
  }
}
```
