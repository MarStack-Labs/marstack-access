# Security design

An access platform is a single point through which privileged traffic flows. That makes it the most
valuable host in an estate, and it means security here is a property of the architecture rather than
a hardening pass at the end.

The design question this document answers is not "how do we keep the gateway from being breached".
It is **"what does an attacker get when the gateway is breached"** — and the answer must be far less
than the estate it protects.

## Threat model

| Adversary | Can do | Must not be able to |
|---|---|---|
| Authenticated platform user | open the sessions they hold a grant for | reach a target outside that grant, land as a principal they were not granted, or open a session that is not recorded |
| Compromised data plane node | observe and proxy the sessions currently flowing through it | reach a target with no active grant, recover the CA private key, or sign a certificate without leaving a record elsewhere |
| Compromised control plane | change policy for future sessions | forge or alter a past audit record, or recover a credential that authenticates to a target |
| Whoever reads a target's `sshd` config | learn which CA the target trusts | derive anything that authenticates to that target |
| Network observer | see ciphertext and connection timing | read session content or replay a session |
| Whoever reads the logs or the database | read operational metadata | recover a certificate, token, password, or private key |

Out of scope for now: an adversary with physical access to a data plane node, and an adversary who
already holds root on the target they are attacking.

## Invariants

These hold everywhere. A change that weakens one is a design change, not a refactor.

1. **Deny by default.** A request with no matching authorization rule is refused. A new endpoint is
   unreachable until it declares who may call it. A session with no active grant does not open.

2. **Validate at the boundary, then trust the value.** Input is parsed into a typed value once, at
   the edge, with unknown fields rejected. Deeper layers never re-parse strings from clients.

3. **No standing credential to a target exists in this process.** There is no target password, no
   target private key, and no CA private key in this binary or in its database. Reading the entire
   database gives an attacker no way to authenticate to any target. This is why the platform is a
   certificate authority client and not a credential vault.

4. **Identity is derived, never asserted.** The principal a session lands as comes from the
   authenticated identity and the matching grant, never from a field in a request body. This is the
   single most common source of privilege-escalation bugs in platforms of this kind.

5. **A session that is not recorded does not open.** A recorder that fails to initialise fails the
   session. Recording is not best-effort, and there is no flag to disable it, because a flag
   eventually defaults wrong.

6. **Authority is scoped when it is minted, not checked when it is used.** A certificate carries one
   principal, one target, one session id, a validity window in minutes, and a `source-address`
   pinning it to the node that requested it. A leaked certificate is useless from anywhere else and
   expires before it can be studied.

7. **The certificate never leaves the data plane.** The user receives a connection, never a
   credential. This is what makes recording unbypassable and revocation immediate.

8. **Audit leaves the process before it is worth deleting.** Events ship to an append-only sink and
   recordings to object storage under an object lock. Neither plane holds a delete credential, so an
   attacker who owns the gateway still cannot erase what it already reported.

9. **Secrets never reach a log or an error body.** `5xx` responses carry a code and a request id;
   the detail stays server-side. Certificates, tokens, and key material are never logged at any
   level, including debug.

10. **Nothing is executed through a shell.** Host commands are built as argument vectors. No string
    interpolation into a command line, ever.

## Where each invariant is enforced

| Invariant | Enforced by |
|---|---|
| Deny by default | `kernel/fault` defaults to `Internal`; authorization middleware refuses routes that declare no policy |
| Validate at the boundary | `httpx.Decode` sets `DisallowUnknownFields` and caps body size; `kernel/validate` |
| No standing credential | there is no schema for one; the signing call lives in `marstack-secrets` |
| Derived identity | authorization middleware puts the identity on the request context; handlers read it from there |
| Recording is mandatory | the recorder wraps the connection a dialer returns, so no dialer can skip it |
| Scoped authority | one place builds the certificate request; principal, target, TTL, and source address are all required fields |
| Certificate stays inside | the mint call returns a connection, not a credential; nothing serialises a certificate to a response |
| Audit ships out | the audit sink is write-only by construction; no delete method exists |
| No secret leakage | `httpx.Wrap` never writes `fault.Unwrap()` to the client |
| No shell execution | `os/exec` with argument slices; `gosec` flags a shell invocation |

## Rules for connection and cryptographic code

This repository is mostly privilege boundaries and network plumbing, so these rules are specific and
non-negotiable.

- **Host keys are verified.** `ssh.InsecureIgnoreHostKey` never appears. A target's host key is
  pinned on first registration and a change fails the session loudly.
- **`crypto/rand` only.** `math/rand` has no legitimate use in this repository.
- **Secrets compare in constant time.** Token and MAC comparison uses `crypto/subtle`.
- **Every connection carries a deadline.** A `net.Conn` without a read and write deadline is a
  resource leak that an unauthenticated peer controls.
- **Validity windows come from one place.** A TTL is never written as a literal at a call site.
- **A parser reads from an untrusted peer with a bounded buffer.** Protocol code caps every length
  it reads before allocating.

## API tokens

A token is `mat_<selector>_<verifier>`: a 4-character prefix, an 80-bit selector, and a 160-bit
verifier, all from `crypto/rand`.

**Lookup is by selector, comparison is on the verifier.** The selector is stored in plaintext under
a unique index, so finding the row is one indexed read. The verifier is stored as a SHA-256 digest
and compared with `crypto/subtle.ConstantTimeCompare`.

The obvious simpler design — hash the whole token, index the hash, look it up — also works and is
one column shorter. It was rejected for two reasons. It hands the secret comparison to SQLite, so
the constant-time rule in this document would be documented and never exercised. And it leaves
nothing safe to write down: the selector is a non-secret handle that can appear in a log line or an
audit record to name *which* token acted, and a hash-only scheme has no such handle.

**SHA-256, not bcrypt or argon2.** Slow hashing exists to make low-entropy human passwords
expensive to guess. The verifier is 160 bits of random data, so a slow hash would add latency to
every authenticated request and remove nothing an attacker could otherwise do. Using argon2 here
would look more careful and be strictly worse.

**Every authentication failure is the same failure.** Malformed, unknown selector, wrong verifier,
expired, revoked, and disabled user all return one code and one message. A distinguishable response
tells an attacker that the selector half was correct, which turns one unguessable secret into two
guessable ones. There is a table-driven test asserting all six are byte-identical.

**The secret is returned once, at issue, and never again.** Nothing stores it, nothing logs it, and
no response can produce it a second time. Losing it means issuing a new one.

**A recognisable prefix is a security feature.** `mat_` makes a leaked token detectable by a secret
scanner that has never heard of this project. `.gitleaks.toml` carries a rule for the format, so a
token pasted into this repository fails the commit. The rule was verified against a token the
running binary actually issued, because a scanner rule that matches nothing is worse than no rule —
it reports success.

## Bootstrap

On a store with no users, the first start creates an `admin` user, issues it a token, and writes the
secret to `<data-dir>/bootstrap-token` with mode `0600`. The log records the **path**, never the
secret, because invariant 9 applies to the bootstrap path too.

Writing to a file rather than printing to the log is what makes possession of the credential mean
something: reading it proves filesystem access to the host, which is the same privilege needed to
read the database anyway. It also means the credential is not duplicated into whatever aggregates
the logs.

Bootstrap runs only when the user count is zero, so a restart does not mint a second admin, and
deleting the file after use closes the window. There is a test asserting the second start writes
nothing.

## Excluded by design

These are not backlog items. Each was considered and rejected, and re-proposing one means arguing
against the reason.

### RDP and VNC

A graphical session cannot be audited without pixels, and this platform does not record pixels. The
two decisions stand or fall together. RDP is also a stack — MCS channels, CredSSP, and layered
bitmap codecs — that would cost more to implement than every other feature combined, for a protocol
this platform's audience barely uses.

### Video recording

Storage, a transcoding pipeline, a retention policy, and a player, in exchange for an artefact
nobody can search. Asciicast is three orders of magnitude smaller and answers "who ran this command
last month" with a query instead of an afternoon.

Honest limitation: asciicast faithfully replays terminal UIs such as `vim`, `htop`, and `tmux`,
because it captures the escape sequences that draw them. Those regions replay correctly but are not
searchable — only the screen being redrawn is visible. The claim is "shell activity is greppable",
not "everything is greppable".

### Command blocking by pattern matching

What a proxy intercepts is a PTY byte stream, not a list of commands. It does not know command
boundaries, shell state, or aliases. Every one of these defeats a blacklist:

```
echo cm0gLXJmIC8=|base64 -d|sh
r''m -rf /
vim, then :!rm -rf /
python3 -c 'import os;os.system(...)'
a heredoc piped into sh
tmux inside the session
```

A blacklist that is bypassed in five minutes is worse than no blacklist, because it makes people
believe the session is constrained.

The platform's actual position: **it decides which account you become on the target. What that
account may do is defined by the target's own configuration.** Dangerous patterns are recorded and
alerted on; they are never claimed to be blocked.

Per-session ephemeral accounts and dynamic sudo policy require code running on the target. That is
an optional add-on behind its own binary, not a reason to put a root daemon on every host.

### A credential vault for targets

Storing target passwords and rotating them reintroduces exactly the standing credential that
invariant 3 exists to remove. The platform authenticates with short-lived certificates or it does
not authenticate.

### Device posture and trust

Requires an agent on every client and hardware attestation to mean anything. That is a separate
product, and a posture check without attestation is a self-reported claim.

## Shift-left tooling

Run locally before every commit, and again in CI:

```sh
make hooks          # install .githooks/pre-commit once per clone
make check          # vet, test, staticcheck, govulncheck, gosec
```

| Tool | Catches |
|---|---|
| `go vet` | misuse of stdlib APIs |
| `staticcheck` | dead code, incorrect nil handling, bad conversions |
| `govulncheck` | known CVEs on a call path reachable from our code |
| `gosec` | command injection, weak randomness, unhandled errors, permissive file modes |
| `gitleaks` | credentials about to be committed |
| CodeQL | taint flows across function boundaries |

`govulncheck` is preferred over a plain dependency audit because it reports only vulnerabilities
that are actually reachable, which keeps the signal usable.

Two things about this pipeline are worth knowing before changing it.

**The Go patch version is a security control.** `govulncheck` fails the build on a standard library
advisory that our code can actually reach, and the fix is usually a patch bump. The version lives in
one place — the `go` directive in `go.mod` — because `actions/setup-go` sets `GOTOOLCHAIN=local` and
therefore ignores a `toolchain` directive. Pinning the toolchain separately produces a build that
passes locally and fails in CI with an identical checkout.

**gitleaks runs as a binary, not as an action.** `gitleaks/gitleaks-action@v2` requires a paid
licence for repositories owned by an organisation and fails the job without one. The scanner itself
is open source and written in Go, so CI installs it the same way it installs the other three and
runs the CLI directly. `make tools` installs the same binary locally.

**CodeQL only runs on a public repository.** Uploading results requires code scanning, which a
private repository gets only with GitHub Advanced Security. The job is gated on visibility rather
than deleted, so it starts working the day the repository opens up. A job that can never pass would
otherwise leave CI permanently red, which trains everyone to stop reading it — a worse outcome than
one fewer scanner.

## Reporting

The project is pre-release and has no users. Once it does, this section gets a contact address and a
disclosure window.
