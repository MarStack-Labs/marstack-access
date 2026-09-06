# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[semantic versioning](https://semver.org/spec/v2.0.0.html). Before 1.0 the API, the CLI and the
on-disk state may change between minor versions.

A release ships one binary, `marac`, which is the control plane, the SSH gateway, the web console
and the client at once.

To cut a release, rename `Unreleased` below to the version and the date, commit, then push the
matching `v` tag. The release workflow takes its notes from the section named after the tag, so a
tag with no section of its own falls back to a bare list of commits.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-06

First tagged release. Pre-1.0: read "What is not covered yet" in
[docs/SECURITY.md](docs/SECURITY.md) before putting this in front of anything that matters.

### Added

- **Agentless SSH access with per-session certificates.** A target opts in with two lines of
  `sshd_config` and nothing is installed on it. Each session gets its own certificate carrying one
  principal, one session id, a validity window in minutes, and a `source-address` pin. `sshd` — not
  this code — enforces all four.
- **The certificate never reaches the user.** The client is handed a connection, not a credential,
  which is what makes recording unbypassable and revocation immediate.
- **Five checks before a session opens:** the target exists, it accepts the principal, its host key
  is pinned, a policy allows it, and an approved grant is live. A refusal names which check refused.
- **Just-in-time access.** A policy is a bound; an approved request inside its window is what makes
  it live. A request cannot be decided by the account that raised it, whatever role that account
  holds. Grants expire from the clock rather than from stored state, so there is no reaper job that
  can stop running.
- **Session recording as asciicast**, output only — commands stay greppable because a shell echoes
  them, and a password typed at a `sudo` prompt is never echoed so never written down. A session
  that cannot be recorded does not open.
- **Recordings uploaded to object storage** under a compliance-mode object lock, with SigV4 written
  here rather than taken from an SDK ([ADR 0001](docs/adr/0001-write-sigv4-rather-than-add-an-sdk.md)).
- **A two-layer audit trail:** a synchronous append-only file, and an asynchronous push to Loki.
  Nothing in this codebase can delete, truncate, or rotate either, and an architecture test fails
  the build if a sink grows a method that could.
- **A kill switch** that closes a live socket from the control plane, and reports honestly when the
  row is open but no socket for it is held here.
- **A web console** at `/console/` with five screens — sessions, requests, targets, policies, and
  the tail of the audit trail. It ships inside the binary, has no build step, and is a client of the
  same guarded API as the CLI, so it cannot become a way around a role. Sign-in swaps a token for an
  `HttpOnly` cookie the page cannot read, and is refused over cleartext.
- **`marac`**, a CLI covering every endpoint, with `--output json` for scripting.
- **Shift-left tooling in CI and in a pre-commit hook:** `go vet`, race tests, `staticcheck`,
  `govulncheck`, `gosec`, `gitleaks`, and CodeQL.

### Known limitations

- **The signing key has no home outside this process.** It sits in a local file named by
  `--dev-ca-key`, and anyone who can read that file can mint access to every target that trusts the
  CA. Moving it behind a signing call in `marstack-secrets` is planned and not built. This is the
  largest open item and it is written up in full as invariant 3 of
  [docs/SECURITY.md](docs/SECURITY.md).
- **A grant expiring does not end a session that is already open.** The check runs once, before the
  session opens. Close it with `marac session kill`.
- **The SigV4 signing has never been checked against a real MinIO.** A canonicalisation mistake
  would surface as a 403 from the store, not as a failing test.
- **Control plane audit events are written after the change commits**, so a crash in between loses
  the event while keeping the change. The session path does not have this problem.

[Unreleased]: https://github.com/MarStack-Labs/marstack-access/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MarStack-Labs/marstack-access/releases/tag/v0.1.0
