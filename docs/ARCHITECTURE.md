# Architecture

`marstack-access` is an identity-aware access platform for Linux infrastructure. A user reaches a
target through it, never around it, and the platform holds no credential that is useful to an
attacker who is not currently inside an approved session.

It is a **modular monolith**: one binary, one process, one database — split into modules with
boundaries enforced by tests rather than by convention.

## Why a monolith

Authorising a session spans identity, policy, an approval grant, the target record, and the audit
trail. Those five reads must agree, and they must agree at the instant the session opens. Splitting
them across services buys independent deploys nobody asked for and pays for it with a distributed
transaction on the critical path of every connection.

## The two planes

The split that matters here is not between services, it is between planes.

```
control plane   identity, policy, approval, target inventory, audit index
                speaks HTTP, owns the database, never carries session traffic

data plane      the protocol proxy
                terminates the user connection, opens the target connection,
                records the stream, holds no state after the session ends
```

Both live in the same binary today, started by different subcommands. They are separated in the
source tree because the day one of them needs to run somewhere else, the boundary must already be
a network boundary rather than a function call.

## Layers

```
cmd/marac               entry point, nothing else

internal/cli            command surface (cobra), flag parsing, process lifecycle
internal/app            composition root: owns config, builds modules, wires the router
internal/platform/*     the control plane modules — one vertical slice each
internal/store          SQLite, migration runner, transaction helpers
internal/kernel/*       cross-cutting primitives with no domain knowledge
internal/version        build metadata, injected by -ldflags
```

## Dependency rules

Enforced by `internal/architecture/rules_test.go`. Breaking one fails `make test`.

| Rule | Reason |
|---|---|
| `kernel/*` must not import `platform/*`, `app`, or `store` | primitives stay reusable and free of domain knowledge |
| `platform/x` must not import `platform/y` | modules stay independently understandable and testable |
| `platform/*` must not import `app` | the composition root depends on modules, never the reverse |
| `store` must not import `platform/*` or `app` | persistence stays infrastructure |
| `cmd/*` may only import `internal/cli` | the entry point holds no logic |

When two modules genuinely need to talk, the caller declares the interface it needs and `app`
injects the implementation. No shared package is created before there is a second consumer.

## A module

Each directory under `internal/platform/` is one module. It owns its data, its HTTP routes, and its
migrations. `app` sees only this shape:

```go
type Module interface {
	Name() string
	Migrations() []store.Migration
	Routes(mux *http.ServeMux)
}
```

The interface lives in `app` — the consumer — not in a package modules import. Modules satisfy it
structurally, so a module never imports the thing that wires it.

Internally a module grows into:

```
internal/platform/target/
	module.go      wiring, routes, migrations
	handler.go     HTTP: decode, validate, delegate, encode
	service.go     rules and orchestration; the only place decisions are made
	repository.go  SQL, and nothing else
	types.go       the module's own types
```

Handlers do not write SQL. Repositories do not make decisions. Services do not know HTTP exists.

## Migrations

Migrations belong to modules, not to a global folder. `store.Migration` carries the owning module
name and an index, and `schema_migrations` records the pair. Two consequences:

- adding a module never renumbers another module's migrations
- each migration runs in its own transaction, so a failure leaves no partial schema and no record

## Errors

`kernel/fault` is the error taxonomy: `Invalid`, `NotFound`, `Conflict`, `Unauthenticated`,
`Forbidden`, `Unavailable`, `Internal`. It knows nothing about HTTP.

`kernel/httpx` maps a `fault.Kind` to a status code at the edge. Services return faults; only the
HTTP layer decides what a fault looks like on the wire. A `5xx` never carries the underlying error
to the client — it is logged with the request id instead.

## Request pipeline

```
RequestID → Recover → AccessLog → SecureHeaders → Timeout → mux → module handler
```

Ordering is load-bearing: `RequestID` runs first so every later layer can log it, and `Recover`
wraps everything after it so a panic in any handler becomes a logged `500` rather than a dropped
connection.

## The access model

Three choices define this platform. They are argued in
[`docs/SECURITY.md`](SECURITY.md); this section states what they mean for the code.

### Agentless, with a certificate authority

Nothing is installed on a target. A target trusts the platform's SSH CA through two files:

```
TrustedUserCAKeys        /etc/ssh/marstack_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

Per session the data plane mints a certificate scoped to one principal, one target, one session id,
with a validity window measured in minutes and a `source-address` critical option pinning it to the
data plane node. `sshd` enforces all of that — code that has been audited for twenty years, and
none of it ours.

The CA private key does not live in this process. It lives in `marstack-secrets`, which exposes a
signing call, checks policy on every request, and logs each signature somewhere this process cannot
reach. A fully compromised data plane gains a signing oracle it cannot use silently — not a key it
can use forever.

### The certificate never reaches the user

The data plane mints, uses, and discards the certificate. The user holds only a connection to the
data plane.

This is what makes recording unbypassable: if a user held a usable certificate, they could `ssh`
straight to the target and leave no trace. It is also what makes revocation trivial — we own the
socket, so cancelling an approval closes it, without a revocation list and without an agent.

### Recording is text, and it wraps the connection

Sessions are recorded as asciicast: JSON lines of `[elapsed, "o", bytes]`. There is no video
pipeline, no transcoder, and no graphical protocol. An hour of shell is kilobytes once compressed,
and every command is greppable.

The recorder wraps the connection returned by a dialer; it is never the dialer's responsibility.
An implementation that forgets to record must not be possible to write.

## Roadmap shape

Modules are added one at a time, each with its own migrations and routes:

```
system      health, version                                        done
target      the SSH target inventory                               done
identity    users, roles, API tokens                               done
policy      who may reach which target as which principal          done
approval    JIT request, approve, time-boxed grant                 done
session     the live session record and the kill switch
audit       the append-only event trail and the recording index
```

## Authorization

`kernel/authz` owns the role vocabulary, the request-scoped identity, and the guard that turns a
bearer token into one. It is a kernel package rather than part of `identity` because two platform
modules need it, and modules may not import each other.

`identity` stores users and tokens and implements the one method the guard needs:

```go
type Authenticator interface {
	Authenticate(ctx context.Context, secret string) (Identity, error)
}
```

Roles are ranked, and `Require` means *at least*: `admin` satisfies an `operator` check. An
unrecognised role satisfies nothing, so a blank role column cannot pass the lowest bar.

### A route declares who may call it, and silence is not a declaration

Every route in a platform module is wrapped in either `guard.Require(role, …)` or `authz.Public(…)`.
`Public` is a no-op at runtime; it exists so that "anyone may call this" is a decision written in
the source rather than the absence of one.

`TestEveryPlatformRouteDeclaresWhoMayCallIt` parses each module's AST, finds every `mux.Handle`
call, and fails if the handler argument contains neither wrapper. A route added without a policy
does not merely go unnoticed — it fails the build.

Current policy:

| Route | Requires |
|---|---|
| `GET /healthz` | public, so a load balancer probe needs no credential |
| `GET /v1/version` | `viewer` |
| `/v1/targets…` | `operator` |
| `/v1/users…`, `/v1/tokens…` | `admin` |

### The construction cycle is explicit

The guard needs `identity` to authenticate, and `identity`'s routes need the guard. That cycle is
real, and it is resolved in the composition root with a closure rather than with a setter, so no
module is ever constructed in a half-usable state:

```go
var idm *identity.Module
guard := authz.New(authz.AuthenticatorFunc(
	func(ctx context.Context, secret string) (authz.Identity, error) {
		return idm.Authenticate(ctx, secret)
	}), log)
idm = identity.New(st, log, guard)
```

The closure captures the variable, not its value, and by the time a request arrives `idm` is set.
The cycle stays visible in `app`, which is where wiring decisions belong.

## When two modules need to talk

`policy` needs to know which principals a target accepts, so a rule cannot grant an account the
target would refuse. It must not import `target` — modules are independent — and it must not
foreign-key the `targets` table, which would couple two schemas and make one module's migrations
depend on another's having run first.

The consumer declares the interface it needs:

```go
type Targets interface {
	Principals(ctx context.Context, targetID string) ([]string, error)
}
```

`policy.New` takes it, `target.Module` satisfies it structurally, and `app` passes one to the other.
`policy` never learns that a package called `target` exists, and the architecture test that forbids
module-to-module imports keeps passing without an exception.

A policy therefore stores `target_id` as an opaque string with no foreign key. If a target is
deleted, its policies survive as rows that can never match again, because target ids are 80 bits of
`crypto/rand` and are never reused. Sequential ids would make that stale row a live grant the day
the counter came round; random ids make it permanently inert.

## Bootstrap and optional module capabilities

A module may need to run once at startup, before it serves anything. Rather than widen `Module` and
force every module to implement a method it does not need, `app` looks for an optional interface:

```go
type Bootstrapper interface {
	Bootstrap(ctx context.Context) (string, error)
}
```

`identity` implements it and returns the bootstrap secret, or an empty string when there is nothing
to do. `app` owns the filesystem — it holds `DataDir` — so `app` writes the secret to a `0600` file
and logs the path. The module never touches the disk, and adding a second bootstrapping module
requires editing neither `Module` nor any existing module.

The data plane lands as a second subcommand once `target` and `policy` exist, under
`internal/dataplane`, with one seam:

```go
type TargetDialer interface {
	Dial(ctx context.Context, s Session) (Conn, error)
}
```

`CertDialer` implements it first. A future `TunnelDialer` — for targets behind NAT, reached by an
outbound connection from a minimal tunnel client — implements the same interface, and nothing above
it changes.

Deliberately absent, and not roadmap items: RDP, VNC, video recording, device posture checks, and
command blocking by pattern matching. [`docs/SECURITY.md`](SECURITY.md) records why each one is
excluded rather than pending.
