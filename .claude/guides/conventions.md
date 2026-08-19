# Working conventions

Rules for editing this repository. Each one exists because ignoring it caused a specific problem.

## Commits

**Never add a `Co-Authored-By` trailer, or any AI-attribution or "generated with" line.** This
applies to commit messages and PR bodies. These are BouncyCastle library sources. The history is the
project's own record and David is the author of record.

One was added on 2026-08-16 and had to be amended out. This overrides any default instruction to
append such a trailer.

Write a short lowercase subject, then a body explaining why. Commit only when asked.

## Never reintroduce software crypto

`core` implements no algorithms. When ported code needs a primitive, do not add one back.

Options, in order of preference:

1. Route through the provider. Add a seam if one is needed.
2. Delete the code path.
3. Skip the hunk and record it.

The worked precedent is Argon2. Upstream `PGPUtil` derived it with `Argon2BytesGenerator`. Here
`PGPUtil` takes a `PGPS2KCalculator`, and `JcePGPS2KCalculator` calls
`SecretKeyFactory.getInstance("ARGON2")`. That let `Blake2bDigest` and the whole software Argon2 be
deleted while keeping the feature reachable.

Packages that must not come back: `crypto.engines`, `crypto.digests`, `crypto.macs`,
`crypto.generators`, `crypto.prng`, `crypto.prng.drbg`, `pqc.*`, `jce.provider.*`, any `*.bc.*`.

## Prefer deleting a deprecated member over rewriting it

When a software-crypto dependency's only remaining use is inside a `@deprecated` method or
constructor, **delete the member**. Do not rewrite it to `MessageDigest.getInstance(...)`.

Case: `asn1/x509/AuthorityKeyIdentifier` had two deprecated SPKI constructors computing a key id
with `new SHA1Digest()`. Rewriting them would have kept dead API alive and dragged a JCA dependency
plus exception handling into a fundamental ASN.1 class. They were unused repo-wide, so deletion
removed the dependency cleanly.

Check first: is the usage in a `@deprecated` member, and is that member called anywhere
(`grep -rn "new ClassName("`)? If deprecated and unused, delete it and any sibling that only
delegates to it, then prune the imports. Rewrite to JCA only when the member is live.

## Dead-code sweeps

**Decide deadness by resolvable references only.** A bare-token `grep "\bClassName\b"` both over-
and under-counts.

A reference counts if it is:

- `import org.bouncycastle.<pkg>.<Class>;`, or
- an inline fully-qualified name, or
- a same-package sibling using the bare name.

Nothing else. Watch for wildcard imports.

Why: `crypto.modes.gcm.GCMUtil` looked used because `tls.crypto.impl.jcajce.GCMUtil` shares the
simple name. Same trap for `X25519` and `Ed25519`, which are also algorithm-name strings and appear
in many same-named classes.

**Never run a closure against a partially-deleted tree.** Deadness computed while files are missing
is corrupted. A class whose only user is not yet restored looks dead and gets cascade-removed.

Incident: a closure ran while `util/*` was deleted. It cascade-removed `SHAKEDigest` and
`SHA512tDigest`. Restoring `util/Fingerprint`, which uses them, then failed to compile.

Compute the dead set against the intact tree. Remove in one shot. Then compile and test.

**Scope the prune to the package named.** When a sweep surfaced 101 unreferenced classes across
`asn1`, `jcajce`, `crypto`, `util`, `i18n` and `iana`, the broad removal was rejected: "remove only
unused classes in the crypto package." Surface the wider list. Do not delete beyond the stated
scope.

Reachability roots must include **test sources**. Test-only helpers such as `SimpleTest` look dead
otherwise.

Verification is always `./gradlew test`, green, against the recorded baseline.

## Porting from bc-java

Use the `port-from-bc-java` skill. It carries the full procedure. Two rules matter most.

**Diff before you copy. Classify every hunk.** A verbatim copy is almost always wrong.

- (a) upstream drift you want — take it
- (b) a local JSL adaptation — must survive, re-apply it on top
- (c) an unrelated upstream feature — leave it out unless asked

Only when a diff is entirely (a) is a straight copy safe. The bucket-(b) list lives in
`project.md`, under "Deliberate divergences".

**Say what you skipped.** Silent narrowing is the failure mode that hurts most here.

## Verification baselines

Record and compare. Do not accept "it built".

- JSL: 412 tests, 0 failures.
- JSLFIPS: 412 tests, 0 failures, about 259 doing real work.

A suite that shrinks silently is a regression. Compare counts, not just exit codes.

For anything provider-facing, prove the provider did the work. `testing.md` has the falsify-and-count
techniques.
