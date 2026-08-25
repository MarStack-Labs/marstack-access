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

On the first start against an empty store it creates an `admin` user and writes that account's token
to `./data/bootstrap-token` with mode `0600`. The log names the path, never the secret. A restart
does not issue a second one.

```sh
export MARAC_TOKEN=$(cat data/bootstrap-token)
rm data/bootstrap-token
```

Every route except `GET /healthz` needs a token. Roles are ranked, and a check means *at least*:

| Route | Requires |
|---|---|
| `GET /healthz` | nothing — a load balancer probe carries no credential |
| `GET /v1/version` | `viewer` |
| `marac target …` | `operator` |
| `marac request create/list/get/cancel` | `operator` |
| `marac request approve/deny/grant` | `admin` |
| `marac user …`, `marac token …`, `marac key …`, `marac policy …` | `admin` |

Create a working account rather than using the bootstrap admin for daily work:

```sh
marac user create --name deployer --role operator
marac token issue --user usr-xxxxxxxxxxxxx --ttl 720h
```

The secret prints once. Nothing stores it, so losing it means issuing another. To take an account
out of service:

```sh
marac token list --user usr-xxxxxxxxxxxxx     # metadata only, never secrets
marac token revoke tok-xxxxxxxxxxxxx          # effective on the next request
marac user delete usr-xxxxxxxxxxxxx           # also revokes every token it holds
```

```sh
curl -s localhost:7443/healthz
curl -s localhost:7443/v1/version
```

Register a target. A target declares the accounts it will accept — `principal` mirrors what its
`sshd` is configured to allow, and at least one is required, because a target nobody can land on is
not reachable.

```sh
marac target register --name db-1 --address 10.0.0.4 \
  --principal deploy --principal postgres

marac target list
marac target get tgt-xxxxxxxxxxxxx
marac target delete tgt-xxxxxxxxxxxxx
```

`--port` defaults to 22 and is omitted from the request when unset, so the platform owns the
default rather than the client. There is no update command yet — delete and re-register.

A registered target is reachable by nobody until its host key is pinned. Pipe it in, usually from
`ssh-keyscan`:

```sh
ssh-keyscan -t ed25519 10.0.0.4 | marac target trust --target tgt-xxxxxxxxxxxxx
```

The fingerprint then shows in `marac target list`, and an unpinned target shows `-`. Replacing a pin
needs `--replace`: a silent replacement is how a man-in-the-middle becomes permanent. Re-pinning the
same key is a conflict too, because a caller that cannot tell "already correct" from "silently
changed" cannot act on either.

Use `-t` when scanning. Without it `ssh-keyscan` emits one line per algorithm, and the platform
refuses an ambiguous scan rather than pinning whichever came first.

Registering a target does not grant anyone access to it. A policy binds a subject — a user or a role
— to one target and an explicit set of accounts:

```sh
marac policy create --name ops-db --role operator \
  --target tgt-xxxxxxxxxxxxx --principal deploy

marac policy list
marac policy delete pol-xxxxxxxxxxxxx
```

A role is matched **exactly**. Granting the `operator` role does not also grant admins — a platform
administrator is not automatically root on every host. A policy cannot name a principal the target
refuses, so a rule that could never work is rejected when it is written rather than when a session
fails.

Ask what a request would decide, without opening a session:

```sh
marac policy evaluate --user usr-xxxxxxxxxxxxx --role operator \
  --target tgt-xxxxxxxxxxxxx --principal deploy
```

```
allowed: true
reason:  granted by policy pol-xxxxxxxxxxxxx
```

A denial always carries a reason, because an undiagnosable denial gets worked around by granting too
much.

A policy is a bound, not an entitlement. Access becomes live only through an approved request:

```sh
marac request create --target tgt-xxxxxxxxxxxxx --principal deploy \
  --reason 'incident 4821' --ttl 2h

marac request list
marac request approve req-xxxxxxxxxxxxx     # admin, and never the requester
marac request grant --user usr-xxxxxxxxxxxxx \
  --target tgt-xxxxxxxxxxxxx --principal deploy
```

The requester is taken from the token — there is no flag for it, and a body naming one is rejected.
A request is refused up front if no policy could ever permit it, so approval is a gate in front of
policy rather than a way around it.

**Self-approval is impossible, including for admins.** The account that raised a request cannot
approve or deny it. A single-account install therefore cannot grant itself access, which is the
control working rather than a bug.

Grants are time-boxed and expiry is derived from the clock, so there is no background job that can
stop running and leave access open.

Register the SSH public key an account will connect with. The key is piped in, so it can come from a
file, a clipboard, or `ssh-add -L`:

```sh
marac key add --user usr-xxxxxxxxxxxxx --name laptop < ~/.ssh/id_ed25519.pub
marac key list --user usr-xxxxxxxxxxxxx
marac key remove key-xxxxxxxxxxxxx
```

The fingerprint shown matches `ssh-keygen -lf` exactly, so a key can be matched by eye. A key may
belong to only one account, and `ssh-dss` and RSA under 2048 bits are refused when the key is added
rather than when a session fails. A key carries no privilege of its own — the account's role and
policies decide everything.

## Connecting

Start the SSH data plane alongside the control plane. It is off unless asked for:

```sh
marac server --ssh-listen 127.0.0.1:2222
```

Then connect with a plain `ssh` client. The username carries where you are going:

```sh
ssh -p 2222 deploy:db-1@gateway
```

```
marstack-access: authorized
  user       alice (operator)
  target     db-1 at 10.0.0.4:22
  principal  deploy
```

An unregistered key gets `Permission denied (publickey)` and learns nothing about what exists.
Anything refused after that — unknown target, a principal the host does not accept, no policy, no
grant — says which check refused it, because a caller who has proved who they are gains nothing from
a blank refusal.

Port forwarding is refused in both directions, and so are agent forwarding, X11, and subsystems. A
gateway that forwards ports is a route into the network that no policy describes and no recording
captures.

An authorised session now reaches the target. Point the gateway at a signing key and connect:

```sh
marac ca init --path ./data/ca
marac server --ssh-listen 127.0.0.1:2222 --dev-ca-key ./data/ca
```

```sh
ssh -p 2222 deploy:db-1@gateway
```

The gateway mints a certificate for that session alone, verifies the target's host key against the
pin, and proxies the shell while recording the output to `./data/recordings/ses-xxxxx.cast`. Play one
back with any asciicast player:

```sh
asciinema play data/recordings/ses-xxxxxxxxxxxxx.cast
grep -o 'sudo [^"]*' data/recordings/*.cast
```

Only output is recorded. A shell echoes what is typed, so commands stay greppable, but a password
typed at a `sudo` prompt is never echoed and so never written down.

Every session is listed, and an admin can close one:

```sh
marac session list
marac session get ses-xxxxxxxxxxxxx      # includes where the recording is
marac session kill ses-xxxxxxxxxxxxx     # admin only
```

A kill that closed nothing says so rather than reporting success — the row may have been opened by a
run that has since stopped. Rows left open by a crash are closed on the next start with a reason
naming the restart, so the list of live sessions does not fill with sessions that are not running.

> `--dev-ca-key` holds the signing key in a local file. Without it the front door still authorises
> but cannot connect, and it says so. See [`docs/SECURITY.md`](docs/SECURITY.md) for what the
> development mode costs.

## Preparing a target

A target trusts the platform through two files and no daemon. Create a signing authority and print
what to install:

```sh
marac ca init --path ./data/ca
```

```
fingerprint SHA256:...

Install this on every target, then reload sshd:

  echo "ssh-ed25519 AAAA..." | sudo tee /etc/ssh/marstack_ca.pub
  # in /etc/ssh/sshd_config
  TrustedUserCAKeys /etc/ssh/marstack_ca.pub
  AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

Sessions authenticate with a certificate minted for that session alone: one principal, pinned to the
gateway's own IP, valid for minutes, and carrying `permit-pty` and nothing else — so port forwarding
and agent forwarding are not granted on the target either.

> `marac ca` keeps the signing key in a local file. That is a development mode, and
> [`docs/SECURITY.md`](docs/SECURITY.md) says what it costs. A production deployment keeps the key in
> `marstack-secrets`, so no process that terminates user traffic ever holds it.

The client talks to `$MARAC_ENDPOINT`, or `--endpoint`, or loopback. `--output json` prints the raw
API response for scripting:

```sh
export MARAC_ENDPOINT=http://control.internal:7443
marac target list --output json
```

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
