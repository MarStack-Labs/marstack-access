# 1. Write SigV4 rather than add an S3 SDK

Accepted, 2026-08-25.

## Context

Invariant 8 in [`../SECURITY.md`](../SECURITY.md) requires recordings to live in object storage under
an object lock, so that an attacker who owns the gateway cannot remove them. The store is MinIO,
which speaks the S3 API.

What the platform needs from that API is one operation: `PUT` an object, with two object-lock headers,
once per session. It never lists, never reads back, and must never delete.

Three options were considered.

**`aws-sdk-go-v2`.** Complete, maintained, and the obvious default. It is also several hundred
thousand lines across a dozen modules, most of which exist for services and behaviours this platform
will never touch. `ENGINEERING-PRINCIPLES.md` says a dependency is justified by work it removes: this
one removes about 150 lines and adds a large surface to every `govulncheck` run and every supply
chain question.

**`minio-go`.** Smaller and closer to the target store, but still a full client with bucket
lifecycle, multipart, notifications, and its own transitive dependencies. Same argument, smaller
number.

**Write the signing.** SigV4 is a documented HMAC chain over a canonical request. It needs
`crypto/hmac`, `crypto/sha256`, and careful string construction. There is no cryptography to invent
— the primitives are standard library, and the risk is in getting the canonical form right.

## Decision

Write it. `internal/kernel/objstore` implements SigV4 and a single `Put`, and there is no method on
it that removes anything.

The risk this accepts is precise and worth naming: a signing implementation that is subtly wrong
fails at the moment it is needed, and the failure looks like a 403 from the store rather than a bug
in this repository. That is mitigated by a golden test that pins the signature for fixed inputs, so a
refactor cannot change signing silently, and by refusing to claim end-to-end correctness that has not
been demonstrated against a running MinIO.

## Consequences

Adding a second object-storage operation is a decision to revisit this, not a small change. If the
platform ever needs listing, multipart, or lifecycle management, an SDK becomes the cheaper option and
this ADR should be superseded rather than stretched.

The gateway's credentials should carry `s3:PutObject` and nothing else. Object lock in compliance mode
means even a store administrator cannot delete an object before its retention expires, but a
credential that can delete makes the code's inability to delete beside the point. That is an IAM
policy on MinIO, not something this repository can enforce, and
[`../SECURITY.md`](../SECURITY.md) says so.
