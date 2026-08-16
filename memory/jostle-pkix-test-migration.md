---
name: jostle-pkix-test-migration
description: Workflow + progress for migrating bc-java/pkix tests into bc-jostle-libs (copy, BC→JSL, skip failures)
metadata:
  type: project
---

Ongoing task: copy missing tests from `bc-java/pkix/src/test` into `bc-jostle-libs/pkix/src/test`, adapt, run, skip failures. bc-java is at `/home/dgh/bc/git/repositories/bc-java`. Baseline 2026-06-08: bc-java/pkix has 158 test files, jostle had 14.

**User-approved adaptation rules:** delete individual tests/imports that depend on `org.bouncycastle.*.bc.*` (the BcXXX software operator/cert packages — absent here); replace BC JCE provider refs with jostle. Concretely the mechanical transform is: `org.bouncycastle.jce.provider.BouncyCastleProvider` → `org.openssl.jostle.jcajce.provider.JostleProvider`; bare `BouncyCastleProvider` → `JostleProvider`; literal `"BC"` → `JostleProvider.PROVIDER_NAME`. (`BouncyCastleProvider` is NOT present in this minimized core; nor are `pqc.*`, `jce.*`, DSA/DH/GOST/3DES/RC2/CAST5/SEED/IDEA engines.)

**Constraints that shape the work:**
- A non-compiling test file breaks the whole module → classify each candidate by ISOLATED compile first (javac against the test classpath) before adding it. Classpath = `core/build/classes/java/main:util/build/classes/java/main:pkix/build/classes/java/main:pkix/build/resources/main:libs/openssl-jostle-1.0-SNAPSHOT.jar:<junit-4.13.2>:<hamcrest-core-1.3>:pkix/src/test/java`.
- Tests come in TWO styles:
  - **JUnit3** (`extends junit.framework.TestCase`): run by gradle directly. **`@Ignore` does NOT work**. Skip a failing test by renaming `testXxx(` → `DISABLED_testXxx(` GLOBALLY in the file (decl AND any `main()`/`suite()` call sites, else compile breaks). If ALL methods get disabled → DROP the class (else JUnit emits a "no tests" warning failure).
  - **SimpleTest** (`extends org.bouncycastle.util.test.SimpleTest`, has `performTest()`+`getName()`, no `testXxx`): gradle's JUnit runner does NOT discover these — they compile but don't run. Add a JUnit bridge (insert before `public String getName(`):
    ```java
    @org.junit.Test
    public void test() throws Exception {
        org.bouncycastle.util.test.TestResult result = perform();
        if (!result.isSuccessful()) { throw new junit.framework.AssertionFailedError(result.toString()); }
    }
    ```
    `perform()` (SimpleTest base) runs performTest and returns a TestResult. To skip a failing SimpleTest, drop the class (its single bridge test is all-or-nothing).
- `CMSTestUtil` (already adapted, in tree) static-inits RSA/EC fine but `dsaKpg`/`dhKpg` are null (no DSA/DH in JSL) → any test class whose static fields call `CMSTestUtil.makeDsaKeyPair()`/`makeDhKeyPair()` throws `ExceptionInInitializerError`/NPE at class load (reported as `initializationError`) and cannot be method-skipped → DROP it.

**Helper script** (`/tmp/migrate.sh`): sed the three substitutions above + inserts the JostleProvider import after the package line if referenced.

**Progress — cms/test (done 2026-06-08):** of 19 missing, migrated 5 that run green and dropped the rest.
- KEPT & passing: `ConverterTest`, `InputStreamWithMACTest`, `NewCompressedDataStreamTest`, `NewCompressedDataTest`; `CMSAuthEnvelopedDataStreamGeneratorTest` (1 test passes; `testNoAuthAttributes`/`testGCMCCM`/`testGCMCCMZeroLength` DISABLED_).
- DROPPED (un-runnable under JSL): `AnnotatedKeyTest`,`MiscDataStreamTest`,`NewSignedDataStreamTest`,`NullProviderTest`,`SunProviderTest` (DSA/DH static-init or Sun/null-provider), `GOSTR3410_2012_256CmsSignVerifyDetached` (GOST), `Rfc4134Test` (SHA1withDSA + test data), `NewAuthenticatedDataStreamTest` (DESede, 3/3 fail), `NewEnvelopedDataStreamTest` & `NewAuthEnvelopedDataStreamTest` (RSA key-transport "unable to encrypt contents key" + EC-key-agree/KEK/ChaCha20 — all methods failed → empty shells), `PQCTestUtil`/`AllTests` (removed pqc deps / suite aggregator). Helper `CMSSampleMessages` not needed once its only user was dropped.
- Net: pkix suite 82 → **95 tests, 0 failures, 12 classes**.

**Progress — cert/test (done 2026-06-08):** of 18 missing, migrated 9 green (4 JUnit3/TestCase + needed `SimpleTest` bridges).
- KEPT & passing: `AttrCertSelectorTest`, `AttrCertTest`, `ConverterTest`, `DANETest`, `X509CertificateReviewerTest`, `X509ExtensionUtilsTest`, and the PQC credential tests `MLDSACredentialsTest`/`MLKEMCredentialsTest`/`SLHDSACredentialsTest` (these use the existing tree `SampleCredentials`, whose accessors are METHODS `ML_DSA_44()` not bc-java's FIELDS `ML_DSA_44` — sed `SampleCredentials\.([A-Z_]+)` → `...()`). Helpers kept: `SampleCredentials` (already present), cert/test `SHA1/SHA256DigestCalculator`.
- DROPPED: `AllTests` (aggregator), `DeltaCertTest`/`PKCS10Test` (`org.bouncycastle.jce.*` removed), `CertPathLoopTest` (no `CertPathValidator` PKIX in JSL), `GOSTR3410_2012_256GenerateCertificate` (GOST), `PQCPKCS10Test` ("only MLDSAParameterSpec is supported"). Helper `PEMData` unused → dropped.
- Net: pkix suite 95 → **109 tests, 0 failures, 21 classes**.

**Progress — pkcs/test (done 2026-06-08): 0 migratable.** All rely on PBE/scrypt/GCM/KWP/GOST/SHA-PBKDF `OutputEncryptor`s JSL doesn't provide. `PKCS8Test` (all 9 fail), `PBETest` (2/2), `PQCPKCS10Test` (1/1), `PKCS10Test`/`AllTests` (removed `jce.spec`/aggregator) — all dropped.

**Progress — tsp/test (done 2026-06-08):** of 10, migrated 3 green (15 tests).
- KEPT & passing: `ERSTestdatenTest`(3), `GenTimeAccuracyUnitTest`(8), `TimeStampTokenInfoUnitTest`(4) — all self-contained, helpers not needed.
- DROPPED: `AllTests`, `NewTSPTest` (`jce.spec`), `PQCTSPTest` (compositesignatures/pqc providers), `ParseTest` (ExceptionInInitializerError — static init on unsupported alg). Helpers `TSPTestUtil`/`SHA1/256DigestCalculator` unused by the kept set → dropped.
- Net: pkix suite 109 → **124 tests, 0 failures, 24 classes**.

**Progress — all remaining no-`.bc.` packages (done 2026-06-08, batched):** staged all 61 remaining candidates at once, BC→JSL transform, auto-added SimpleTest bridges, iteratively dropped non-compiling files (removed `jce.*`/`pqc.*`/`compositesignatures` deps), then one run + triage. Net: pkix suite 124 → **196 tests, 0 failures, 44 classes**. Per package now running: est(5 classes/32), mime(4/21), cades(1/3), cert.cmp(1/4 — InvalidMessagesTest, 3 disabled), cert.path(3/3 — incl CertPathValidationTest; CertPathTest kept as a DATA-HOLDER with its bridge REMOVED), cert.ct(1/1), dvcs(1/2), its(1/2 — ITSJcaJceBasicTest, 2 disabled), mozilla(1/1), pkix(2/3). 
- Dropped 0-pass: ElgamalDSATest, TestHostNameAuthorizer, CheckNameConstraintsTest, IDPRelativeNameTest, MTCNewFeaturesTest, ETSIEncryptedDataTest, ITSCertLoadTest, RevocationTest, + the SimpleTest CertPath/MTC ones; plus ~8 that didn't compile (jce/pqc/composite).
- **KEY GOTCHA:** a SimpleTest BRIDGE method carries `@org.junit.Test`, so it runs by ANNOTATION — renaming it `DISABLED_` does NOT skip it. To skip/neutralise a bridge, REMOVE the `@Test` method entirely (e.g. CertPathTest data-holder). Only JUnit3 `testXxx` (no annotation) is skipped by renaming.

**Recurring failure causes to expect in other packages:** unsupported algs (DSA, DH, GOST, 3DES, RC2, CAST5, SEED, IDEA, ECDSA-variants JSL lacks), RSA key-transport for CMS recipients, missing test-data resources, and `.bc.` operator builders.

**Progress — the 37 `.bc.`-importing tests (done 2026-06-08): salvaged 2 classes / 4 tests.** Stripping `.bc.` imports alone salvages nothing — every one actually USES the `Bc*` classes. The one clean, common substitution is `new BcDigestCalculatorProvider()` → `new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider(JostleProvider.PROVIDER_NAME).build()` (JSL supplies the digests). With that swap + strip-`.bc.`-imports + iterative compile-prune, survivors were `TestSMIMESigned`(2 pass) and `MultipartParserTest`(2 pass, 7 disabled). Everything else dropped: the `Bc*`-named tests (BcCertTest/BcSignedDataTest/BcEnvelopedDataTest/BcPKCS10Test/BcAttrCert* — they TEST the software path), and tests whose `.bc.` use is in CMS content encryptors / PEM decryptors / PKCS12 MAC / etc. that have no JSL path (TestSMIMEEnveloped, CMSTimeStampedData*, PKCS12UtilTest, …). The `.bc.` tests are largely software-path duplicates of already-migrated Jca coverage, so low marginal value.
- Net: pkix suite 196 → **200 tests, 0 failures, 46 classes**.

**pkix MIGRATION COMPLETE (2026-06-08).** Both the no-`.bc.` (full sweep) and `.bc.` sets processed. pkix went 14 → 46 test classes, **200 passing tests, 0 failures**.

**Progress — tls module (started 2026-06-08):** the `tls` module had no tests. Same workflow (classpath adds `:pkix` + `tls` main classes; `/tmp/tls_cp.txt`). Of 117 bc-java/tls tests, batch-pruned to compiling survivors then triaged. KEPT & passing (12 tests / 5 classes): `jsse/provider/test/ConfigTest`(2), `InstanceTest`(3), `tls/test/ByteQueueInputStreamTest`(5), `OCSPTest`(1), `TlsUtilsTest`(1). Dropped 0-pass: `SSLServerSocketTest`, `TrustManagerFactoryTest` (need BCJSSE/SSL server), `JVMVersionTest`, and `test/AllTest` (aggregator, named `AllTest` not `AllTests`). The bulk of tls/test (protocol client-server suites, DTLS, full JSSE) was pruned at compile (need BC crypto / `tls.crypto.impl.bc` which is absent — only `jcajce` impl is present) — and many copied tls/test files are mock infrastructure (MockTls*/TlsTestUtils/cert resources) that COMPILE but don't run (used only by the dropped suites); harmless clutter, could be pruned by reachability from the 5 kept classes.

**Progress — tls harness port to JcaTlsCrypto (done 2026-06-08):** rewrote `TlsTestUtils` to Jca-only (dropped the `tls.crypto.impl.bc` branches + `loadBc*` helpers; kept the `JcaTlsCrypto` path) and added a `TlsTestUtils.createTestCrypto()` factory = `new JcaTlsCryptoProvider().setProvider(new JostleProvider()).create(new SecureRandom())`. Transform `migrate4` then maps `new BcTlsCrypto(...)` → `TlsTestUtils.createTestCrypto()` and the `BcTlsCrypto` type → FQN `JcaTlsCrypto`, unlocking the mock servers + protocol suites (survivors 39→86). After triage tls went 12→**16 tests / 8 classes**: added `tls/crypto/test/JcaTlsCryptoTest`(2; 7 methods disabled in base `TlsCryptoTest` — DH/HKDF/legacy+1.2+1.3 signatures/EC-domain), and **`TlsTestCase`(1) + `DTLSTestCase`(1)** — a basic TLS/DTLS handshake DOES complete through JcaTlsCrypto+JSL. Dropped: the Bc-named duplicates (`BcTlsCryptoTest`/`BcTlsProtocol{Kem,Hybrid}Test` — identical to Jca after the crypto swap) and the parameterised protocol suites `Tls/DTLS Protocol{,NonBlocking,PSK,Kem,Hybrid}Test`, `Tls13PSKProtocolTest`, DTLS-retransmission — all 0-pass: the elaborate cipher-suite/named-group/ML-KEM-group negotiations don't complete through JSL (even `testMLKEM*` TLS handshakes fail, though raw ML-KEM KEM works). `TlsTestUtils` is hand-maintained (not from bc-java verbatim) — re-running the migration must NOT overwrite it.

**Progress — pg module (done 2026-06-08):** `pg` had no tests; deps core+util+jostle (NOT pkix); main has only `openpgp/operator/jcajce` (no `bc` operators). Classpath `/tmp/pg_cp.txt`. Of 130 bc-java/pg tests, batch-pruned to 37 compiling, triaged to **18 passing / 15 classes, 0 failures**: armoring/compression/packet/util/feature/marker/regex unit tests (`Armored*Test`, `PGPCompressionTest`, `PGPPacketTest`, `PGPUtilTest`, `BytesBooleansTest`, `KeyGripCalculatorTest`, …). Dropped 0-pass: `DSA2Test`/`PGPDSATest` (DSA), `PGPPBETest`/`PGPUnicodeTest` (PBE passphrase), `PGPRSATest`, `PGPParsingTest`, `SExprTest` — crypto round-trip/keyring tests needing DSA/PBE/specific ops JSL lacks.

**Progress — mail module (done 2026-06-08):** `mail` (S/MIME) deps core+util+pkix+jostle+`libs/{mail,activation}.jar`; classpath `/tmp/mail_cp.txt`. Of 18 bc-java/mail tests, only **1 passes**: `mail/smime/test/PipedStreamThreadStuckTest` (a plumbing/threading test). All the S/MIME signing/encryption round-trips dropped (CMS crypto operators / `.bc.`). A few orphan helpers (`SMIMETestUtil`, `SHA1DigestCalculator`, `DummyCertPathReviewer`, …) copied but unused.

**Progress — util module (done 2026-06-08):** `util` had no tests; deps core+jostle. Classpath `/tmp/util_cp.txt`. The 84 bc-java/util tests are pure ASN.1 encoding (asn1.{cmc,cmp,cms,crmf,esf,ess,icao,isismtt,misc,smime,util}, oer) — no `.bc.`, no crypto. Batch-migrated to **69 tests / 51 classes, 0 failures**. (`asn1/icao/test/CscaMasterListTest` first failed for a missing test resource — reinstated by copying `util/src/test/resources/org/bouncycastle/asn1/icao/test/masterlist-content.data` from bc-java; it's loaded via `getClass().getResourceAsStream`, so resources go under `<module>/src/test/resources/<package path>`.) Highest-yield module after pkix.

Whole-repo test state 2026-06-08: **pkix 200 + util 69 + pg 18 + tls 16 + mail 1 = 304 passing, 0 failures** (clean `clean test`). All five testable satellite modules now have migrated tests; bulk of un-migrated tests need DSA/DH/GOST/3DES/RC2/PBE/CertPath-PKIX/BCJSSE/Bc-software-operators JSL doesn't provide.

Remaining bc-java/pkix tests are not migrated by design (need DSA/DH/GOST/3DES/RC2/PBE/CertPath-PKIX/Bc-software-operators that JSL doesn't provide); they are dropped, not skipped-in-place. To migrate more, JSL would need to grow those capabilities. Plus 37 missing WITH `.bc.` imports (need method-level deletion of `.bc.` usages). See [[jostle-libs-project]].
