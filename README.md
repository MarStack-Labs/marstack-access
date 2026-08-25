# marstack-access

Identity-aware access platform for Linux infrastructure. Users reach a target through it, never
around it, and it holds no credential that is useful to an attacker who is not inside an approved
session.

> Pre-release. No tagged releases, no stability guarantees, and nothing you care about should run
> behind it yet.

## What makes it different

Most bastions are a credential vault with a proxy attached: they store target passwords, rotate
them, and hand them out. That concentrates every standing credential in the estate onto the one host
an attacker most wants.

This one inverts that.

- **No standing credentials.** There is no target password, target key, or CA private key in the
  binary or its database. Reading the whole database gives an attacker no way to authenticate to any
  target. Sessions authenticate with certificates minted per session, scoped to one principal, one
  target, and a validity window measured in minutes.
- **Agentless.** Nothing is installed on a target. A target opts in with two files in its `sshd`
  configuration, and `sshd` — not our code — enforces the certificate's principal, expiry, and
  source address.
- **Tamper-evident audit.** Events ship to an append-only sink and recordings to object storage
  under an object lock. Neither plane holds a delete credential, so owning the gateway does not
  erase what it already reported.
- **Greppable sessions.** Recordings are asciicast, not video. "Who ran this command last month" is
  a query, not an afternoon of playback.

## Deliberate boundaries

These are excluded by design, not pending. See [`docs/SECURITY.md`](docs/SECURITY.md) for the
reasoning behind each.

| Not supported | Because |
|---|---|
| RDP, VNC | a graphical session cannot be audited without pixels, and this platform records text |
| Video recording | unsearchable, and it drags in transcoding, retention, and a player |
| Command blocking by pattern | a PTY byte stream is not a command list; every blacklist is trivially bypassed |
| A credential vault for targets | reintroduces the standing credential the design exists to remove |
| Device posture checks | meaningless without hardware attestation, which is a separate product |

## Requirements

- Go 1.26 or newer
- Linux or macOS for development; Linux for deployment
- No hypervisor, no privileged container, no kernel modules — a small VPS is enough

## Quickstart

```sh
make hooks      # install the pre-commit hook, once per clone
make tools      # install the security scanners
make build
./bin/marac version
./bin/marac server
```

The control plane binds `127.0.0.1:7443` by default and creates its database under `./data`. It
binds loopback rather than every interface on purpose — exposing it is a deployment decision, not a
default.

```sh
curl -s localhost:7443/healthz
curl -s localhost:7443/v1/version
```

Register a target. A target declares the accounts it will accept — `principals` mirrors what its
`sshd` is configured to allow, and at least one is required, because a target nobody can land on is
not reachable.

```sh
curl -s localhost:7443/v1/targets \
  -H 'Content-Type: application/json' \
  -d '{"name":"db-1","address":"10.0.0.4","principals":["deploy","postgres"]}'

curl -s localhost:7443/v1/targets
curl -s localhost:7443/v1/targets/tgt-xxxxxxxxxxxxx
curl -s -X DELETE localhost:7443/v1/targets/tgt-xxxxxxxxxxxxx
```

`port` defaults to 22. There is no update endpoint yet — delete and re-register.

## Development

```sh
make check      # vet, test, staticcheck, govulncheck, gosec
```

`make check` must pass before every commit. The pre-commit hook runs a faster subset.

## Documentation

| Document | Covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | the modular monolith, the two planes, module layout, the access model |
| [`docs/SECURITY.md`](docs/SECURITY.md) | threat model, invariants, rules for connection code, exclusions |
| [`docs/ENGINEERING-PRINCIPLES.md`](docs/ENGINEERING-PRINCIPLES.md) | working conventions, principles, and the rules that are easy to violate |

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
