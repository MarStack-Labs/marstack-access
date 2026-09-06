# 2. Vendor the design system rather than depend on it

Date: 2026-09-06

Status: accepted

## Context

The console has to look like the rest of the platform. The house design system is Meridian, a set
of CSS custom properties and component classes — surfaces, status colours, spacing and type scales,
the pill and table and button styles — already used by `marstack-cloud`. Reusing it is not
optional; two products in the same family that disagree about what "pending" looks like are worse
than one that has no theme at all.

The question is how the file gets here. Three options were considered.

**Depend on it as a Go module.** The theme declares a module path, so this looks natural. It is
not: the module is not published, it is not a separate repository, and it contains no Go. Making
this work means `GOPRIVATE`, an SSH or token credential in CI, and a release process for a
repository that does not exist yet — all to fetch one stylesheet. The framing is also wrong. Go
modules version Go packages, and nothing about `go.sum` verification tells us the CSS is correct.

**Fetch it at build time.** A `make` target that curls or clones the theme. This trades a committed
file for a network dependency in the build, which is the wrong direction for a security gateway.
A clean checkout would stop building the day the source moves, and the artefact would depend on
when it was built rather than on what is in the tree.

**Link to it from the page.** A `<link>` to a CDN or a sibling host. Ruled out by the content
security policy, which is `default-src 'self'` with no exceptions: an external stylesheet host is a
party that can change how this console reads, including hiding a button.

## Decision

Copy `meridian.css` into `internal/console/assets/` and commit it. It is embedded with the rest of
the console by `go:embed` and served from this origin.

Provenance is this file. The source is the `marstack-theme` tree in the author's workspace; the copy
is byte-for-byte, unmodified, and page-specific styles live in `console.css` alongside it rather
than as edits to the vendored file. Updating the theme means copying it again and reading the diff.

## Consequences

A clean checkout builds with `go build` and no network. The published binary contains everything it
serves, and the policy stays absolute — there is no third-party origin in the page at all.

The cost is real and accepted: this copy can fall behind. Nothing detects that, and nothing will
until the theme has a repository and a version. When it does, this decision is worth revisiting —
but the trigger is the theme becoming a published artefact, not the console growing another screen.

Keeping `console.css` separate is what makes the update cheap. Because no local change is ever
written into the vendored file, re-copying can never lose work, and any diff that appears in
`meridian.css` came from upstream.
