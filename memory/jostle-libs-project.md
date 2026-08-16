---
name: jostle-libs-project
description: The bc-jostle-libs project — compatibility libraries (core/util/pkix/mail/pg/tls) for the OpenSSL Jostle JSL provider
metadata:
  type: project
---

Building `bc-jostle-libs`: BouncyCastle satellite libraries (util, pkix, mail, pg, tls) rebuilt from `../bc-java` (v1.85-SNAPSHOT) to run against the **OpenSSL Jostle** provider instead of bcprov, plus a new minimal **core** module supplying the `org.bouncycastle` asn.1/util/support classes the jostle jar does not ship.

**The model is `../bc-fips-libs-java`**: each satellite module copies bc-java sources verbatim, compiles against a provider jar in `libs/` instead of bcprov, re-jars with a tweaked manifest, and keeps a `*-chk.sh` drift-checker + `list.txt` of source deltas vs bc-java.

Jostle provider facts: package `org.openssl.jostle`, provider name **`"JSL"`** (`JostleProvider.PROVIDER_NAME`), JCA/JCE-only, delegates to OpenSSL via JNI/FFI, multi-release jar (Java 8→25, built with Java 25). Built jar lives at `../openssl-jostle/jostle/build/libs/openssl-jostle-0.1-SNAPSHOT.jar`; staged into `bc-jostle-libs/libs/`. The jar exports **zero `org.bouncycastle` classes** — that gap is why `core` exists.

**JSL capability (corrected 2026-06-06 by user — my earlier "PQC+symmetric only" note was WRONG):** the JSL provider is broadly capable. Prov* classes: AES/ARIA/CAMELLIA/SM4/DESede (symmetric), RSA (Cipher/KPG/KeyFactory/RSASSA-PSS + SHA{1,224,256,384,512}withRSA), EC (KPG/KeyFactory/ECDH KeyAgreement + SHA{1,224,256,384,512}withECDSA), ED (Ed25519/Ed448 + variants), MD (MessageDigests incl SHAKE), Mac, PBKDF/Scrypt, ML-DSA/ML-KEM/SLH-DSA. So RSA/EC/Ed/digests ARE available through JSL. Still NOT present (would fall back / fail): DSA, GOST/ECGOST, DH, NTRU, and other legacy/PQC-extras. NOTE: `BouncyCastleProvider` was removed from the libs core, so tests/code reference provider name "JSL" / `org.openssl.jostle.jcajce.provider.JostleProvider`, not "BC".

Module dep graph (prov is absorbed into core): core ← util ← pkix ← {mail, tls}; pg ← util. Build: Gradle 9.1 wrapper, release 8, JDKs BC_JDK8/11/17/21/25 available (default java 17). See [[jostle-libs-core-closure]] for the core-sizing analysis and [[jostle-libs-core-recipe]] for the exact core build.

**Build status — ALL SIX MODULES COMPILE & JAR GREEN (clean build, 2026-06-05):** bccore-jsl, bcutil-jsl, bcpkix-jsl, bcmail-jsl, bcpg-jsl, bctls-jsl. `./gradlew clean build -x test` succeeds.

Per-module deltas applied (vs bc-java 1.85):
- `core` — see [[jostle-libs-core-recipe]] (1590 files; later also added `jcajce/provider/symmetric/util` for pg's JceAEADCipherUtil).
- `util` — ZERO changes (compiled clean against core+jostle, confirms core sizing).
- `pkix` — deleted all `.../bc/` packages (82 files); patched `operator/jcajce/JcaContentSignerBuilder` + `JcaContentVerifierProviderBuilder` (stripped composite-private/public-key build paths + LMS digest derivation; composite *AlgorithmSpec* signing retained); `cms/jcajce/JceCMSKEMKeyWrapper` only needed 4 dead PQC imports removed — ML-KEM CMS works via the generic non-RSA KTS branch through JCA.
- `mail` — deleted `bc/` packages; removed stale `mail/smime/examples/CreateSignedMail.java` (used cert.bc).
- `pg` — deleted `bc/` packages; switched `openpgp/api/OpenPGPImplementation.getInstance()` default from `BcOpenPGPImplementation` to `jcajce.JcaOpenPGPImplementation`.
- `tls` — overlaid the `jdk1.5` multi-release source root (10 files: the jsse `*Util` classes the base `java/` tree references); deleted `bc/`; patched `tls/crypto/impl/PQCUtil` (removed the two `get*SignatureScheme(MLDSA/SLHDSAParameters)` methods — callers only use the OID/`supports` methods). NOTE: `jdk1.9`/`jdk17`/`jdk25` multi-release overrides NOT yet applied — current jar is release-8 baseline only; proper MR-jar packaging is a follow-up.

General rule established: delete every `org.bouncycastle.*.bc` leaf package in the satellite modules (BC low-level software-crypto API, replaced by JSL via JCA); keep the `jca`/`jce` builder variants and patch out composite-signature / LMS / BC-PQC-param branches.

**Runtime test harness (task 7) — DONE.** JSL provider confirmed loading on this box (linux/x86_64, Java 17 JNI; jar bundles its own libcrypto.so.3 + interface libs). Tests live in `pkix/src/test/java/org/bouncycastle/jsl/test/` (base class `JostleProviderTestBase` installs provider "JSL" reflectively; jostle jar is already an `implementation` dep so it's on the test classpath; gradle forks a Java-17 JVM). `./gradlew clean build` green. Suite: 7 tests, 6 pass, 1 skip.
- `MLDSACertTest` (2), `SLHDSACertTest` (2): self-signed ML-DSA-44/65 + SLH-DSA-SHA2-128F/SHAKE-192F certs built via JcaX509v3CertificateBuilder + JcaContentSignerBuilder(JSL), verified via JcaContentVerifierProviderBuilder(JSL). Plus a wrong-key negative test.
- `MLDSACmsSignedDataTest` (1): CMS SignedData, ML-DSA-87 signature via JSL + SHA-256 digest via JDK default (the canonical split — JSL has no MessageDigest). Verify from PUBLIC KEY, not cert (cert->java.security conversion needs an X.509 CertificateFactory JSL lacks).
- `AesGcmTest` (1): AES-256-GCM round-trip + AEAD tamper rejection through JSL.
- `MLKEMEnvelopedDataTest` (1, @Ignore): blocked by [[jostle-provider-aes-oid-gap]] — JSL doesn't alias AES to CMS content/wrap OIDs. Re-enable once the provider adds aliases.

KEY GOTCHA for JSL test code: never route X.509 CertificateFactory / cert conversion through provider "JSL" (it has none) — verify from PublicKey, and use the JDK default provider for digests. ML-DSA/SLH-DSA/ML-KEM/AES by NAME work; AES by per-mode OID does not.

**Remaining polish (not started):** manifests/OSGi/Automatic-Module-Name; proper multi-release jar packaging for tls (jdk1.9/jdk17/jdk25 overrides); per-module `*-chk.sh` drift-checkers + `list.txt` like bc-fips-libs; broaden tests once the AES-OID gap is fixed in jostle.
