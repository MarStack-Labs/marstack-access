## What this changes

<!-- One paragraph. What is different after this that was not true before. -->

## Why

<!-- The problem, not the patch. Link the issue if there is one. -->

## How it was verified

<!--
Not "tests pass". What did you break on purpose to check the test would notice?
If you did not add a test, say why one is not possible here.
-->

## Checklist

- [ ] `make check` passes
- [ ] A change to behaviour has a test that fails without it
- [ ] I broke the new rule on purpose and watched a test go red
- [ ] No comments added to code
- [ ] `CHANGELOG.md` updated under `Unreleased`, if this changes what a release contains
- [ ] `docs/SECURITY.md` updated, if this changes a security property — including when the change
      makes it read less well
