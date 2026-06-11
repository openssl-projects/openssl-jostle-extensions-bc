# CLAUDE.md

## What this is

`bc-jostle-libs` is a set of BouncyCastle satellite libraries (CMS/PKIX/cert, mail, OpenPGP, TLS) **rebuilt from bc-java** to run against the **OpenSSL Jostle ("JSL") JCA provider** instead of BC's own software crypto. The libraries keep BC's high-level APIs (asn.1, operator, cert, cms, …) but delegate all primitive crypto (ciphers, signatures, KEM, digests, RNG) to OpenSSL via JSL.

Modules (see `settings.gradle`): `core`, `util`, `pkix`, `mail`, `pg`, `tls`. `core` is a **minimized** bc-java core — see below.

The JSL provider itself lives in a **separate repo**, `../openssl-jostle` (`org.openssl.jostle.*`, provider name `"JSL"`, class `org.openssl.jostle.jcajce.provider.JostleProvider`). It is consumed here as a **prebuilt jar**: `libs/openssl-jostle-1.0-SNAPSHOT.jar` (version pinned by `jostleVersion` in `gradle.properties`).

## Build & test

```bash
./gradlew assemble          # build all *-jsl jars (release 8, default JDK 17)
./gradlew test              # run tests (pkix/tls/pg/mail have migrated tests; core/util have none)
./gradlew :pkix:test --tests "org.bouncycastle.jsl.test.*" --rerun-tasks
```

JDK toolchains come from `BC_JDK8/11/17/21/25` env vars (`gradle.properties`). Tests are **JUnit 4.13.2** but most copied bc-java tests are JUnit3 style (`extends junit.framework.TestCase`).

**Artifacts.** Each module produces `bcXxx-jsl-<version>.jar` plus `-sources.jar` and `-javadoc.jar`. The main jar is an **OSGi bundle** built via the `biz.aQute.bnd.builder` plugin (7.0.0; bc-java uses 7.1.0): the root `build.gradle` sets `Bundle-*` headers + per-module `Export-Package` (the `osgiExports` map, patterns mirrored from the matching bc-java module) and a versioned `Import-Package` range `[bundle_version, maxVersion)` (`maxVersion` in `gradle.properties`); bnd computes the actual imports/`uses:`. `bundle_version` is the OSGi-legal form of `version` (snapshots → `X.Y.Z.<days-since-epoch>`).

## Critical constraints (read before editing)

- **This repo is NOT a git checkout** (no `.git`, no backups). Before deleting/overwriting anything, **move-to-backup** (e.g. `.something.bak/`) rather than `rm`, and never `rm -rf` with `..` traversal.
- **Minimized core.** `core` was reduced to what the satellites + JSL actually reach. Absent: `org.bouncycastle.jce.provider.*` (so **no `BouncyCastleProvider`**), `pqc.*`, most `crypto.engines`/`digests` (no DSA/DH/GOST/3DES/RC2/CAST5/SEED/IDEA software impls), the `BcXXX` (`*.bc.*`) operator/cert builders. JSL supplies AES(+GCM/KW)/RSA/EC/Ed/ML-DSA/SLH-DSA/ML-KEM/SHA/HMAC etc. How core is sized + the closure-prune recipe: memory `jostle-libs-core-closure`, `jostle-libs-core-recipe`.
- **Editing the JSL provider means editing `../openssl-jostle`** and rebuilding its jar. A full `:jostle:jar` there **requires JDK 25** (the multi-release `java25` FFI source set); only JDK ≤21 is installed here, so the full build fails. Workaround: recompile just the changed class(es) with JDK 17 (`--release 9`) against the existing jar and **hot-patch** them into `libs/openssl-jostle-1.0-SNAPSHOT.jar` at BOTH the base path and `META-INF/versions/9/...` (the running JVM 17 loads the versioned entry). Such hot-patches are stopgaps — the durable artifact needs a real JDK-25 rebuild.
- **`jostleVersion` (gradle.properties) must match the libs jar filename.** The provider is consumed as `libs/openssl-jostle-${jostleVersion}.jar`; the actual artifact (and the openssl-jostle repo) is `1.0-SNAPSHOT`, so `jostleVersion=1.0-SNAPSHOT` even though the libraries' own `version` is `1.85.0-SNAPSHOT`. A mismatch makes `jostleProviderJar()` resolve to a missing file → the provider drops off the classpath and test compiles fail with "package org.openssl.jostle... does not exist" (often hidden until a `clean` forces real recompilation).

## Conventions

- **Provider OID aliases** (in `../openssl-jostle` `Prov*` classes): register with `provider.addAlias(type, name, new ASN1ObjectIdentifier("<oid>"))` — the `ASN1ObjectIdentifier` overload registers both the bare and `OID.`-prefixed forms. Do not add a String-based helper.
- **Tests** install JSL directly: `Security.addProvider(new JostleProvider())`, and use `JostleProvider.PROVIDER_NAME` (often via a `private static final String BC = JostleProvider.PROVIDER_NAME;` shim) wherever bc-java used `"BC"`.

## Migrating bc-java tests (ongoing)

Copying tests from `../bc-java/pkix/src/test` into `pkix/src/test`. Rules: drop tests/imports depending on `*.bc.*`; replace `BouncyCastleProvider`→`JostleProvider`, `"BC"`→`JostleProvider.PROVIDER_NAME`. Tests are either JUnit3 (`extends TestCase`) or BC `SimpleTest` (`performTest()`, not discovered by gradle — add a JUnit `@Test` bridge calling `perform()`). JUnit3 `@Ignore` does NOT work — skip a failing test by renaming `testXxx`→`DISABLED_testXxx` (globally, incl. `main()`/`suite()` call sites); if all methods get disabled, drop the class. Isolated-compile each candidate before adding it (a non-compiling file breaks the whole module). Full workflow + progress + per-package failure causes: memory `jostle-pkix-test-migration`.

## State of the JSL provider work (this is what the provider can do for CMS/certs)

ML-DSA, SLH-DSA, ML-KEM, EC, RSA, AES (incl. GCM + RFC 3394/5649 key-wrap) work today. Recently added in `../openssl-jostle`: SPKI OID aliases for ML-DSA/SLH-DSA/ML-KEM (KeyFactory + Signature); `KeyInfoCanonicalizer` (strips a non-conformant NULL `parameters` from SPKI/PKCS8 AlgorithmIdentifiers before OpenSSL — FIPS 203/204/205 require absent params); `validateKeyAlg` accepts key-wrap-spelled key labels (`AESWrap`); `MLKEMKTSCipherSpi` + `GCMAlgorithmParameters` enabling the **CMS ML-KEM KEMRecipientInfo** path (RFC 9629). Details/design: memory `jostle-mlkem-cms-kts-design`, `jostle-mldsa-spki-encoding-gap`, `jostle-provider-aes-oid-gap`.

## More context

The `memory/` directory holds detailed project notes (build recipe, core-closure analysis, ML-KEM/ML-DSA design, test migration, conventions). `build-analysis/` was a one-time jdeps scratch dir and has been deleted — regenerate via the jdeps step in `jostle-libs-core-closure` if needed.
