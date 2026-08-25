# Security policy

## Supported versions

None yet. `marstack-access` is pre-release, has no tagged releases, and should not sit in front of
anything you care about.

## Reporting a vulnerability

Open a private security advisory through GitHub on this repository. Please do not open a public
issue for a vulnerability.

Include what you did, what happened, and what you expected. A reproduction against a local
deployment is the most useful thing you can send.

Findings that let a session reach a target outside its grant, land as a principal it was not
granted, open without being recorded, or continue after its grant is revoked are the highest
severity in this project.

## Design and threat model

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model, the invariants the code is expected
to hold, the rules that apply to connection and cryptographic code, and the scanners that run on
every commit.
