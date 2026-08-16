---
name: port-from-bc-java
description: Port or refresh a source file, class or test from the upstream bc-java checkout into this JSL fork. Use whenever the task involves copying from ../bc-java, resyncing a file with upstream, migrating bc-java tests, or pulling in an upstream refactor. Covers dependency triage (what does NOT exist here), the local JSL adaptations that must survive a resync, and the verification order.
---

# Porting from bc-java into the JSL fork

Upstream lives at `/home/dgh/bc/git/repositories/bc-java`. This repo keeps BC's high-level APIs but
delegates every primitive to the OpenSSL Jostle ("JSL") provider, and its `core` is deliberately
minimized. **A verbatim copy is almost always wrong.** Work through the steps below in order.

## Module map

| upstream | here | note |
|---|---|---|
| `bc-java/core/src/main/java/...` | `core/` | minimized — see "what is absent" |
| `bc-java/prov/src/main/java/org/bouncycastle/jcajce/...` | `core/src/main/java/org/bouncycastle/jcajce/...` | prov's jcajce support lands in **core** here |
| `bc-java/pkix`, `pg`, `mail`, `tls` | same names | |
| `bc-java/util` (asn1 satellites) | `util/` | |

The provider itself is a **separate repo** (`../openssl-jostle`), consumed as the prebuilt jar
`libs/openssl-jostle-1.0-SNAPSHOT.jar`. Do not try to fix provider bugs from this repo.

## 1. Diff before you copy — classify every hunk

If the file already exists here, never overwrite it blind:

```bash
diff -u pg/src/main/java/org/bouncycastle/openpgp/operator/PGPUtil.java \
        ../bc-java/pg/src/main/java/org/bouncycastle/openpgp/operator/PGPUtil.java
```

Sort every hunk into one of three buckets:

- **(a) upstream drift you want** — the reason you are porting. Take it.
- **(b) a local JSL adaptation** — must survive. Re-apply it on top of the upstream text.
- **(c) unrelated upstream feature** — leave it out unless asked. Upstream files often carry drift
  that has nothing to do with your task (new packet types, new helper indirection).

Only when the diff is *entirely* bucket (a) is a straight `cp` safe.

### Local adaptations that bite

These are real divergences already in the tree; reverting them compiles fine and breaks at runtime:

- **AEAD associated data.** Local code calls `JceAEADCipherUtil.setUpAeadCipher(...)` /
  `updateAAD`; upstream passes the AAD in `AEADParameterSpec`'s associated-data field. JSL's OpenSSL
  ciphers **do not read that field**, so the tag is computed without the AAD and decryption auth
  fails. Seen in `JcePBEKeyEncryptionMethodGenerator`, `JcePBEProtectionRemoverFactory`.
- **Default provider.** `JcaOpenPGPImplementation` uses `(Provider)null` (JDK default), not
  `new BouncyCastleProvider()` — that class does not exist here.
- **Provider name.** `JostleProvider.PROVIDER_NAME` wherever upstream writes `"BC"`.
- **Removed algorithm branches.** EC/GOST/DSA paths are variously dropped or replaced with throwing
  stubs (`JcaPGPKeyPairGeneratorProvider.generateEC*`). Do not "restore" them from upstream.
- **Helper indirection.** Upstream may have introduced helpers this fork lacks (e.g. jcajce
  `OperatorUtils.createDefaultHelper()`). Adapt to the local idiom
  (`new OperatorHelper(new DefaultJcaJceHelper())`) rather than importing the new helper, unless the
  helper is small, clean, and genuinely wanted.

## 2. Triage the dependencies before copying

Walk the upstream file's imports. Anything in these groups is **absent here**:

- `org.bouncycastle.*.bc.*` — the `BcXXX` software operator/cert builders. Drop the code path or
  switch to the `Jca`/`Jce` variant with `.setProvider(JostleProvider.PROVIDER_NAME)`.
- `org.bouncycastle.jce.provider.*` — no `BouncyCastleProvider`.
- `org.bouncycastle.pqc.*` — JSL owns PQC.
- Most of `org.bouncycastle.crypto.{engines,digests,generators,macs,modes,prng}` — the software
  primitives. Check what actually survives before assuming; the tree is pruned continuously.

**Never reintroduce software crypto to satisfy a port.** If the upstream code needs a primitive,
add a *provider seam* instead. The worked precedent is Argon2: upstream `PGPUtil` derives it with
`Argon2BytesGenerator`; here `PGPUtil` takes a `PGPS2KCalculator`, and `JcePGPS2KCalculator` routes
to `SecretKeyFactory.getInstance("ARGON2")`. That let `Blake2bDigest` and the whole software Argon2
be deleted while leaving the feature reachable the moment JSL grows the service. See
`memory/jostle-pg-argon2-provider-gap.md`.

If a needed class lives in bc-java's `prov` module, copy it into `core` here — and strip any
software-crypto coupling on the way in (e.g. `Argon2KeySpec`'s constants were inlined so it no longer
imports `Argon2Parameters`).

## 3. Verify, in this order

1. **Tests only:** isolated-compile the candidate first — one non-compiling test file breaks the
   whole module's test compilation. Classpath is recorded in `memory/jostle-pkix-test-migration.md`.
2. `./gradlew :<module>:compileJava`
3. `./gradlew assemble`
4. `./gradlew test` — pkix/tls/pg/mail have tests; core/util have none. Compare counts against the
   numbers in the memory notes; a suite that shrinks silently is a regression.
5. **Probe changed runtime paths.** A green suite proves little when no test covers the path you
   touched. Write a throwaway `main()` in the scratchpad, compile it against
   `*/build/libs/*.jar` + `libs/openssl-jostle-1.0-SNAPSHOT.jar`, and confirm the behaviour — in
   particular that an unsupported path fails with a clean, explanatory exception rather than an NPE.

**Gotcha:** `jostleVersion` in `gradle.properties` must match the `libs/openssl-jostle-*.jar`
filename. A mismatch makes the provider silently drop off the classpath; failures look like
"package org.openssl.jostle... does not exist" and may not surface until a `clean`.

## 4. Porting tests specifically

Mechanical transform: `BouncyCastleProvider` → `JostleProvider`, `"BC"` →
`JostleProvider.PROVIDER_NAME`, and add the import. Then:

- **JUnit3** (`extends junit.framework.TestCase`) runs directly, but `@Ignore` does **not** work.
  Skip a test by renaming `testXxx` → `DISABLED_testXxx` *globally* (declaration and every
  `main()`/`suite()` call site). If every method ends up disabled, drop the class.
- **`SimpleTest`** subclasses are not discovered by gradle. Add a `@Test` bridge calling `perform()`
  and failing on `!result.isSuccessful()`.
- A class whose **static initialiser** touches an unavailable algorithm (DSA/DH key pairs via
  `CMSTestUtil`) throws at class-load and cannot be method-skipped — drop it.

Full workflow, the exact classpath, and the per-package record of what was migrated vs dropped:
`memory/jostle-pkix-test-migration.md`.

## 5. Finishing

- Say plainly what you skipped and why — dropped test methods, omitted upstream hunks, paths that now
  throw. Silent narrowing is the failure mode that hurts most here.
- Prefer deleting a dead upstream dependency over porting it (`memory/prefer-deleting-deprecated-over-rewriting.md`).
  Before deleting, use import/FQN reachability, not bare-token grep — comments and same-name classes
  in other packages produce false hits both ways (`memory/dead-code-sweep-method.md`).
- Commit only when asked. Short lowercase subject, body explaining *why*.
  **No `Co-Authored-By` or other AI-attribution trailer** (`memory/no-co-authored-by-trailer.md`).
