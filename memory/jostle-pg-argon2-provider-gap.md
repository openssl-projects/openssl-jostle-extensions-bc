---
name: jostle-pg-argon2-provider-gap
description: OpenPGP Argon2 S2K is now provider-backed (SecretKeyFactory ARGON2) and JSL doesn't implement it yet
metadata:
  type: project
---

On 2026-08-16 `pg`'s S2K layer was resynced to bc-java's `PGPS2KCalculator` refactor so that
Argon2 (RFC 9580 sec. 3.7.1.4) is derived through the JCA provider instead of a software engine:
`PGPUtil.makeKeyFromPassPhrase` now takes a `PGPS2KCalculator`, and `JcePGPS2KCalculator` calls
`SecretKeyFactory.getInstance("ARGON2")` with `org.bouncycastle.jcajce.spec.Argon2KeySpec` (copied
into core from bc-java `prov`, with the variant/version constants inlined). That let
`Blake2bDigest`, `Argon2BytesGenerator`, `Argon2Parameters` and the whole `crypto.generators`
package be deleted from core.

JSL has no `SecretKeyFactory.ARGON2`, so every Argon2 S2K path now fails with
`PGPException: unable to derive Argon2 key: no such algorithm: ARGON2 for provider JSL`.
That hits reading/writing v6 keys and SKESKv6 packets that use Argon2 - i.e. what GnuPG/Sequoia
emit by default for v6 - including `OpenPGPMessageGenerator`'s SEIPDv2 branch and
`JcaAEADSecretKeyEncryptorFactory`'s default. No test covers it, so `./gradlew test` stays green.

**Why:** the goal was removing software crypto (Blake2b) from core without permanently amputating
Argon2 - the calculator seam keeps the feature reachable the moment the provider grows the service.

**How to apply:** to restore Argon2, add a `SecretKeyFactory.ARGON2` to `../openssl-jostle` backed by
OpenSSL 3.2+'s `argon2id` EVP_KDF. It must accept `org.bouncycastle.jcajce.spec.Argon2KeySpec`
(memory in KiB, key length in bits); JSL doesn't ship that class, so it has to read the spec
reflectively or via a shared interface. Cost-parameter clamping already happens above the provider in
`PGPUtil` (max memory exp 24, passes 10, parallelism 16, all `org.bouncycastle.argon2.max_*`
overridable). See [[jostle-libs-core-closure]], [[jostle-libs-project]].
