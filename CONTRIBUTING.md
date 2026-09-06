# Contributing

Thanks for taking the time. This is pre-1.0, so the shape of things can still change — if you are
about to spend real effort, open an issue first and we can agree on the approach before you write
it.

This is a security gateway. That does not make contributing harder, but it does change what a
finished change looks like: the bar is not "it works", it is "here is what would have to break for
this to be wrong, and here is the test that notices".

## Getting set up

Go 1.26 and nothing else. No database server, no message queue, no bundler, no `node_modules`.

```sh
git clone git@github.com:MarStack-Labs/marstack-access.git
cd marstack-access

make hooks      # once per clone: install the pre-commit hook
make tools      # once: staticcheck, govulncheck, gosec, gitleaks
make check      # the gate: vet, race tests, staticcheck, govulncheck, gosec, gitleaks
make run        # a gateway on 127.0.0.1:7443 with a console at /console/
```

The pre-commit hook runs the same checks CI does, so a commit that lands locally lands in CI. If
they ever disagree, that is a bug in the setup and worth an issue on its own — it has happened once
already, and the cause was `GOTOOLCHAIN`.

## What a change looks like

**A change to behaviour comes with a test that fails without it.** The bar is not coverage, it is
whether the test would notice. The check that actually works: break the rule you just wrote — invert
the condition, delete the guard, reverse the ordering — and see whether a test goes red. If none
does, the test describes the code rather than holding it to anything.

That is not a slogan here. Several tests in this repository passed while proving something weaker
than they claimed, and every one of them was found this way rather than by reading.

**Boundaries are enforced, not suggested.** `internal/architecture/rules_test.go` parses the AST of
every file and fails the build when a layer reaches somewhere it should not, when a route declares
no policy, when an audit sink grows a method that could shorten the trail, when `math/rand` appears,
or when host key verification is disabled. Adding a rule there is a welcome kind of contribution.
The reasoning behind each is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Refuse rather than guess.** When input is ambiguous or the state is not what was expected, the
platform says no and says why. A silent fallback is a bug that surfaces somewhere else, later,
usually to someone else.

**Error messages are for the person reading them at 3am.** Say what happened and what they can do
about it. `invalid_limit` is a code; "limit must be at most 500" is the message. Both.

**No comments.** Explain a trap in the commit body or in `docs/`, where it is read by someone
deciding whether to trust this thing, rather than only by someone already inside the file.

## Things that will be turned down

Not because they are bad ideas, but because they are decisions this project has already made. Each
one is argued in [docs/SECURITY.md](docs/SECURITY.md) under "Excluded by design":

- RDP or VNC support, or session video recording
- Command blocking by pattern matching
- A credential vault that stores target passwords or keys
- Device posture checks

A dependency is also a decision. Adding one needs a sentence on the work it removes, and that
sentence has to survive comparison with the standard library. `docs/adr/0001` is what turning one
down looks like.

## Commits

Conventional commits — `feat:`, `fix:`, `docs:`, `test:`, `build:`, `perf:`, `refactor:`, `chore:` —
with an optional scope like `feat(console):`. Subject in the imperative, under 72 characters.

The body says **why**, and names any trap a future reader would otherwise hit. If you found a bug
while writing the change, say how you found it; that is often more useful than the fix.

Keep unrelated changes in separate commits.

## Documentation

Anything that changes what a release contains goes in [CHANGELOG.md](CHANGELOG.md) under
`Unreleased`.

A change to a security property changes [docs/SECURITY.md](docs/SECURITY.md) in the same commit —
including when the change makes the document *less* flattering. There is precedent: invariant 3 was
rewritten to admit the signing key has no home outside the process, rather than left reading as
though it did.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).
