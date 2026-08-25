# Engineering principles

Read `docs/ARCHITECTURE.md` before adding a module. Read `docs/SECURITY.md` before touching
anything that parses input from a peer, opens a connection, handles a certificate or a token, or
writes an audit record.

This repository is mostly privilege boundaries. Assume every file you touch is one.

## Language

Code, comments, documentation, commit messages, error strings, and log messages are **English**.

## Commits

- One small, working task per commit. `make check` must pass before committing.
- Conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `build:`.
- Subject in the imperative mood, under 72 characters.
- The body explains **why**, and names any trap a future reader would otherwise hit.

## Principles

These are not decoration. Each one has a concrete consequence in this repo.

### KISS

Prefer the stdlib: `http.ServeMux` with `"GET /path"` patterns, `log/slog`, `database/sql`,
`crypto/*`. A dependency is justified by work it removes, not by convenience it adds.

`golang.org/x/crypto/ssh` is the one dependency this platform cannot avoid, because implementing the
SSH transport ourselves would be the least safe thing in the repository. Everything else needs an
argument.

### YAGNI

Do not build for a requirement that does not exist yet. No shared package before there is a second
consumer. No interface before there is a second implementation, with one exception: `TargetDialer`,
where the second implementation (`TunnelDialer`) is a committed roadmap item.

If you catch yourself writing an abstraction to be "ready", delete it and write the concrete thing.

### SoC

Two separations, and neither blurs.

Layers within the control plane:

| Layer | Does | Must not |
|---|---|---|
| handler | decode, validate shape, delegate, encode | contain rules or SQL |
| service | rules, orchestration, transactions | know that HTTP exists |
| repository | SQL | make decisions |
| kernel | mechanism | know any domain |

Planes:

| Plane | Does | Must not |
|---|---|---|
| control | decide, record, persist | carry session bytes |
| data | move bytes, record the stream | decide whether a session is allowed |

`kernel/fault` exists precisely so services can fail meaningfully without importing `net/http`.

### DRY, with a limit

Deduplicate mechanism — request decoding, error mapping, id generation, migration running, TTL
resolution, deadline setting.

Do **not** deduplicate two rules that merely look alike today. Two modules validating a name may
share `validate.Name`; two modules with coincidentally identical business rules may not share a
service.

### SOLID where it earns its place

- **S** — a module owns one resource. `system` owns health and version; it does not grow features.
- **O** — extend by adding a module or a dialer, not by adding a branch to existing code. Adding a
  module must not require editing another module.
- **L** — a dialer that cannot honour an operation declares it up front. It must not accept the call
  and fail halfway, because halfway through a session is after the user believes they are connected.
- **I** — the consumer declares the interface it needs. `app.Module` lives in `app`, not in a package
  modules import.
- **D** — modules depend on interfaces they declare; `app` injects the implementation.

## Definition of done

```sh
make check      # vet + test + security scans
```

- New behaviour has a test. New failure mode has a test.
- New input path validates before use, and rejects unknown fields.
- New connection code sets read and write deadlines, and bounds every length it reads.
- Errors carry a `fault` kind; nothing internal leaks to a client.
- No new secret, certificate, or token reaches a log line, at any level.
- `docs/ARCHITECTURE.md` updated if a boundary or a module changed.
- `docs/SECURITY.md` updated if an invariant, an adversary, or an exclusion changed.

## Standing rules that are easy to violate

- **A certificate is never serialised into a response, a log, or an error.** If a struct holding key
  material grows a JSON tag, that is a bug. The user receives a connection, never a credential.
- **The recorder wraps the connection, never the dialer.** Recording must not be a responsibility a
  dialer implementation can forget. If you find yourself adding recording inside a dialer, the seam
  is in the wrong place.
- **`ssh.InsecureIgnoreHostKey` does not appear in this repository**, including in tests. A test that
  needs a host key generates one.
- **`math/rand` does not appear in this repository.** `crypto/rand` for everything, including test
  fixtures, so the habit never has an exception.
- **`internal/architecture/rules_test.go` is the architecture.** If a boundary needs to change,
  change the rule deliberately in the same commit — do not work around it with an import alias.
- **A "temporarily disable recording" flag is not an acceptable debugging aid.** Add a test seam
  instead.
