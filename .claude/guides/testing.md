# Testing bc-jostle-libs

Reference for how the test suite selects a crypto provider, and what each provider can do.
Read before changing provider selection, adding a FIPS gate, or trusting a green run.

## Symptom index

Match the error first. Each row gives the cause and the action.

| symptom | cause | action |
|---|---|---|
| `no such algorithm: <X> for provider JSLFIPS` | FIPS module lacks `<X>` | Gate the test. See **Which gate to use**. |
| `IllegalStateException: unable to rebuild certpath`, or any `NoSuchProviderException` naming `JSL` on a `fipsTest` leg | A library class named a provider through `DefaultProviderName`, whose default is `"JSL"`, but only `JSLFIPS` is registered | Nothing to fix in the test: `JslTestProvider.install()` repoints `DefaultProviderName` at the installed provider. Make sure the test calls `install()`. See **Naming a provider from library code**. |
| `KeyStoreException` for any `PKCS12*` type on JSLFIPS | PKCS#12 is withdrawn from JSLFIPS entirely | Use JSL for keystores. There is no FIPS keystore. |
| `InvalidKeyException` from `initSign` naming `digest not allowed` | SHA-1 signature *generation* refused (verification is allowed) | Sign with SHA-256. See **Prefer adapting over skipping**. |
| `RSA key size 1024 is out of range [2048, 16384]` | FIPS minimum modulus | Use 2048 under FIPS. |
| `padding PKCS1Padding not supported` | RSA PKCS#1 v1.5 key transport not approved | Gate. No workaround. |
| `certificate_unknown(46); No support for rsa_pss_pss` | SPKI `AlgorithmIdentifier` lost in key re-derivation | Check the round trip. Fixed provider-side; see **RSA-PSS certificates**. |
| `'resource' doesn't specify a valid private key` under FIPS | `JcaTlsCrypto` advertised a scheme the provider cannot do | Fix capability reporting, do not gate. See **Capability reporting**. |
| handshake `internal_error(80)` under FIPS | Same as above | Same as above. |
| `NoClassDefFoundError` on a whole test class | Missing algorithm inside a `static { }` block | See **Static initialisers**. |
| `AssumptionViolatedException` reported as a failure | Class extends `junit.framework.TestCase` | Use an early `return`, not an assumption. |
| `ProviderException: DSA key generation is not supported` | Module config refuses DSA generation (e.g. 3.5.x `-pedantic`); import/verify still work | Catch the typed refusal or probe with `canSign`. Config-dependent, not version-dependent. **`CMSTestUtil.makeDsaKeyPair()` catches `ProviderException` broadly and returns null, so a genuine DSA keygen DEFECT reads as "not generatable here" too** - if DSA coverage goes quiet unexpectedly, look at the exception before trusting the null. |
| `NoSuchAlgorithmException` for X25519/X448 on JSLFIPS | 3.5.x module loaded; XDH registration is probed per module | Gate on `supports("KeyAgreement.X25519")`. Intended contract. |
| `private key was created by a different Jostle provider` | Both Jostle providers registered at once | Only one is installed per run. See **One provider per run**. |
| `private key was created by a different Jostle provider instance` | A SECOND instance of the SAME provider - something removed it and `install()` built another, while a cached key generator kept making keys for the first | `JslTestProvider` holds one instance per JVM and re-registers that one. See **One instance per JVM**. |
| `InvalidKeyException` from `initSign`/`initVerify` on JSLFIPS `NoneWithRSA`, often as TLS 1.3 `internal_error(80)` | Deliberate: raw RSA is non-approved, so JSLFIPS registers the name against an SPI that cannot resolve. See **Raw RSA on JSLFIPS**. | Probe with `canSign("NoneWithRSA", "RSA", 2048)` and use another credential. Do not file it as a gap. |
| FIPS suite passes in milliseconds | Gradle replayed a cached result | `TEST_FIPS_LIB` must be a task input. See **Gradle**. |
| A leg reports 0 failures but the work looks absent | JUnit3 gates return early, which counts as a PASS | Read the `silent-skips` figure in the leg summary. See **Reading a leg summary**. |
| `--tests` run fails tests that pass in a full run | The filtered subset loses the provider registration other classes' `TestSetup` performs | Never measure from a filtered run. Run the whole task. |
| `Test data directory bc-test-data not found` | `TestResourceFinder` walks UP from the working directory, and `BC_TEST_DATA_HOME` is not wired into `build.gradle` | Run from inside the tree, or put a `bc-test-data` symlink in a parent. Bites in a git worktree. |

## The two runs

| task | provider | when |
|---|---|---|
| `./gradlew test` | JSL (`JostleProvider`) | always |
| `./gradlew fipsTest` | JSLFIPS (`JostleFIPSProvider`) | only when `TEST_FIPS_LIB` is set |

```bash
export TEST_FIPS_LIB=/Users/meganwoods/openssl/openssls/osx_3_1_2/lib/ossl-modules/fips.dylib
./gradlew test fipsTest --continue
```

Current state, against jar `1df49922` on 2026-09-09 (sha256 `1df4992222a988fa591c1948cb9db759edd7cf684f6fca57958a1343417559a5`, from openssl-jostle `64f2bc1`):

| leg | tests | failures | reported skips | silent skips | doing real work |
|---|---|---|---|---|---|
| JSL | 445 | 0 | 0 | 0 | 445 |
| JSLFIPS 3.5.8 | 445 | 0 | 5 | 63 | 377 |
| JSLFIPS 3.1.2 | 445 | 0 | 16 | 94 | 335 |

"Doing real work" is tests minus both skip columns, which is only knowable because the leg summary
reports silent skips - see **Reading a leg summary**. Run BOTH modules: they skip different tests,
in both directions, and a green run on one proves nothing about the other. Differing skip counts
are also how you tell a real FIPS run from a replayed cached one.

Use `--continue` for `fipsTest`. Without it Gradle stops at the first failing module.

## State of the disabled tests

59 test methods are declared `DISABLED_testXxx` and run on no configuration, so they are outside
every count the legs report. 59 is the count of DECLARATIONS; grepping the prefix loosely finds
more lines, because `main()` and `suite()` call sites mention it too. Each carries a one-line reason, measured on 2026-09-08 and re-measured where
noted. What they are:

| cause | tests | item |
|---|---|---|
| CMS/PKCS#8 resolves the algorithm by **OID** and the provider registers no such alias | 9 | MT-72 |
| the ML-KEM and RSA-KEM KTS ciphers accept X9.44 KDF3 only; CMS asks for HKDF or KDF2 | 11 | MT-73 |
| `Cipher ETSIKEMwithSHA256` absent — BC's ETSI ITS KEM name, with no JCA-canonical spelling to switch to | 4 | MT-80 |
| CCM `init` demands a `GCMParameterSpec` where GCM auto-generates its own | 2 | MT-82 |
| `Cipher.updateAAD` after content — illegal per the JCE contract, so not fixable provider-side | 1 | MT-70 |
| JSLFIPS mints EC keys on `sect*` curves with cofactor ≠ 1, then cannot ECDH-derive on them | 1 | MT-71 |
| the fork ships no `CertPathValidator` SPI, so a test asserting a BC path-validation message cannot pass | 1 | — |
| algorithms absent on every configuration — SEED, CAST5, RC2, RC4, Twofish, GOST, ECMQV, Camellia `KeyGenerator` | 30 | — |

The count and this table must agree at every commit. Recount with
`grep -rh 'public void DISABLED_test' --include="*.java" */src/test | wc -l` rather than trusting
the prose: it read **62** while the real figure was 57, an intermediate value nobody corrected.

**A reason comment is a measurement with a date on it, not a permanent label.** The four
`ETSIEncryptedDataTest` rows were filed under MT-69, the Spi-less `SecureRandom` NPE. Re-measuring
them on jar `1df49922` peeled off three layers and none of them was MT-69:

1. MT-69's NPE is fixed. What replaced it was `rand up-call failed with code -99`, cause swallowed.
2. MT-79 then made the cause readable, and it was **test-side**: a 32-byte `FixedSecureRandom`
   running short of OpenSSL's 64-byte EC keygen draw, `ArrayIndexOutOfBoundsException: last source
   index 64 out of bounds for byte[32]`. BC's keygen draws 32, so the fixture was sized for BC.
   The determinism was never needed — the test round-trips a plaintext — so it now uses a real
   `SecureRandom`.
3. Underneath that, `brainpoolP256r1` is absent from the FIPS modules but **present** on JSL, so
   the curve needs a per-configuration probe gate rather than a flat exclusion.
4. Underneath THAT, all four rows stop at the same place: `Cipher ETSIKEMwithSHA256`, MT-80.

Four wrong reasons deep. Each layer looked like the whole answer until it was removed, which is the
argument for re-measuring a gate rather than reading its comment.

The seven OIDs behind MT-72, resolved from the constants this repo ships rather than from memory —
`id_aes128_CCM` `2.16.840.1.101.3.4.1.7`, `id_aes192_CCM` `…1.27`, `id_PBKDF2`
`1.2.840.113549.1.5.12`, `id_alg_CMS3DESwrap` `1.2.840.113549.1.9.16.3.6`,
`dhSinglePass_cofactorDH_sha1kdf_scheme` `1.3.133.16.840.63.0.3`,
`dhSinglePass_stdDH_hkdf_sha256_scheme` `1.2.840.113549.1.9.16.3.19`, and the BSI ECKA-EG arc
`0.4.0.127.0.7.1.1.5.1.1.3`, which this core carries no constant for.

**Name an OID precisely or not at all.** Writing `1.3.133.16.840.63.0.3` as "the X9.63 OID" was
enough for a reader downstream to fill the gap wrongly, as `stdDH-sha256kdf` — a different scheme,
different KDF and no cofactor. `dhSinglePass_stdDH_hkdf_sha256_scheme` is a DIFFERENT arc,
`…1.9.16.3.19`. To resolve one, reflect over the `ASN1ObjectIdentifier` constants in the shipped
`core` (538 of them) rather than searching bc-java's sources, which build OIDs by branching so a
literal search finds nothing.

## Gating a class, and why not to

`NewSignedDataTest`, `NewEnvelopedDataTest` and `CMSAuthEnvelopedDataStreamGeneratorTest` each
carried a class-level `runTest()` gate keyed on `isFips()`, hiding 107 tests on both FIPS legs.

**Its stated reason was accurate; only its scope was wrong.** The three causes it named — SHA-1
signature generation, RSA PKCS#1 v1.5 key transport, Triple-DES — account for 46 of the 55 failures
measured when the gate is removed. What was wrong is that it applied three true reasons to all 107
tests, including the 52 that pass. A gate that is right about the cause and wrong about the scope
still costs the same coverage as one that is simply wrong, which is the point worth remembering.

Removing it recovered 52 executions on a 3.5.8 module and 48 on a 3.1.2 one. The replacements are
per-test probes, and two lessons came out of building them:

- **A test can fail for DIFFERENT reasons on different modules, so one gate may not be enough.**
  `testDSAEncapsulated` finds a null DSA fixture on a `-pedantic` 3.5.8 module, where keygen is
  refused, and refused SHA-1 DSA signing on a 3.1.2 module, where keygen works. It needs both gates.
- **Check that a probe fires only where it should.** Gating `testErroneousKEK` on Triple-DES
  ENCRYPTION skipped it on 3.5.8, where it passes: it needs Triple-DES only to RESOLVE. A probe
  that fires more widely than the dependency is a class gate wearing a new hat.


## Reading a leg summary

Each leg prints one line per module:

```
pkix fipsTest: tests=275 failures=0 reported-skips=4 silent-skips=55 (silent-skips = gated executions, not distinct tests)
```

That is a real line from the 3.5.8 leg, not an illustration.

**`silent-skips` is the number that matters.** A gate in a `junit.framework.TestCase` subclass
returns early, and JUnit records that as a PASS, so `tests=275 failures=0` is equally true of a
module doing its work and of one gated almost entirely out. JSL gates nothing, so its `silent-skips`
is 0 and any non-zero value there is worth reading.

Why the counter exists, as a dated example of what it caught: on 2026-09-08, before the CMS class
gates were narrowed, the JSLFIPS legs reported 5 skips on a 3.5.8 module and 16 on a 3.1.2 one while
silently gating 108 and 125 tests. Both legs read as "412 tests, 0 failures". Those two numbers are
history, not the current state - the table under **The two runs** has that.

Two limits, both deliberate:

- It counts `[skipped]` MARKER LINES, so it measures gated executions, not distinct tests. Gradle
  writes `<system-out>` at suite level rather than per `<testcase>`, so per-test attribution cannot
  be recovered from the XML. The line says so itself.
- Every gate must therefore print `[skipped]`. A gate that returns silently is invisible to this
  and to everything else. If you add one, print.

The summary is wired with `finalizedBy`, not `doLast`, because a `Test` task throws on failure
inside its own action - `doLast` would be skipped exactly when the numbers matter. The `fipsTest`
summary mirrors the leg's `onlyIf`, so it cannot report a previous run's XML as though it were this
one's.

## Probing a capability

The rules below each cost a wrong answer on 2026-09-08.

**A `Cipher` TRANSFORMATION never has a `getService` entry.** Providers register the base algorithm
(`AES`, `DESEDE`, `CAMELLIA`), so `getService("Cipher", "DESede/CBC/PKCS5Padding")` is null even
where the cipher works perfectly. For a transformation, only a functional probe answers. Reading
that null as "absent" reported Triple-DES and Camellia as missing from JSL when both work.

**Enumerate the provider's services before probing, never guess names.** Guessed names produced
false "absent" readings that hid real capabilities: RSA-KEM is `Cipher RSA-KTS-KEM-KWS`, CBC-CTS is
`Cipher AES/CTS/NOPADDING`, the KDFs are per-digest (`KBKDF-HMAC-SHA256`, `SSKDF-SHA256`,
`SSHKDF-SHA256`), and the X9.63 agreements are `KeyAgreement ECDHWITHSHA256KDF`. Walk
`provider.getServices()` first. As a cross-check that you are probing the intended jar, the service
counts at jar `1df49922` are JSL 346, JSLFIPS 191 on a 3.1.2 module and 277 on a 3.5.8 one, and they
should match jostle's own `SERVICES.md` for the commit the jar came from.

**A functional probe must do what the CALLER does.** Supply the parameter set, the spec, the mode,
the transformation, and the same NAME FORM the caller uses - or its "no" is the probe's omission,
not the provider's refusal. Four false "absent" readings on 2026-09-08 came from this one mistake:

| probe as written | what it reported | what the caller does |
|---|---|---|
| `getService("Cipher", "DESede/CBC/PKCS5Padding")` | absent | providers register the base name; only a functional probe answers |
| guessed service names | RSA-KEM, CBC-CTS, 3 KDF families absent | enumerate `provider.getServices()` first |
| `KeyPairGenerator("ML-DSA").generateKeyPair()` | registered-but-refusing | `initialize(MLDSAParameterSpec.ml_dsa_65)` first; family names need a parameter set |
| `KeyAgreement("ECDHWITHSHA256KDF")…generateSecret("AES")` | absent | `JceKeyAgreeRecipient` passes the key-wrap **OID**, not a name |

| probing `Cipher.getInstance("AESWRAP")` for a CMS test | usable, so ungate | CMS resolves by **OID** from the message, not by JCA name |

**The caller is whoever actually performs the lookup.** For CMS and PKCS#8 that is the layer
resolving an algorithm by OID out of the message, so a probe by JCA name asks the wrong caller
entirely. That mistake put 22 tests on an ungate list they could not pass: `AESWRAP`,
`AES/CCM`, `RSA-OAEP` and ECDH-with-KDF all work by name, while `Cipher 1.2.840.113549.1.9.16.3.6`,
`KeyGenerator 2.16.840.1.101.3.4.1.7`, `SecretKeyFactory 1.2.840.113549.1.5.12` and three
`KeyAgreement` OIDs are not registered. When the test drives a layer, probe through the layer or
read what the layer looks up.

The OID one cost 22 tests ungated and re-disabled; the `generateSecret("AES")` one cost a reported
provider defect that did not exist. Read the caller before writing the probe.

Probe each DIRECTION separately where they can differ. A 3.5.8 module serves Triple-DES for
decryption and refuses encryption with a typed `InvalidKeyException`, so "is DESede there" has no
single answer. The no-argument `canInitCipher` hardcodes a 32-byte AES key and a 12-byte IV, so it
answers "no" for any algorithm shaped differently - give the probe the key and IV sizes the
algorithm actually takes.

**Report registration and usability separately.** `REG/REFUSED` is a real state here - see
**Raw RSA on JSLFIPS**.

## Provider selection

All selection goes through one class:
`testsupport/src/main/java/org/bouncycastle/jsl/test/JslTestProvider.java`.
The root `build.gradle` adds that directory to every module's `sourceSets.test`.
The modules share no other test code.

| call | returns |
|---|---|
| `JslTestProvider.install()` | registers the provider under test, idempotent |
| `JslTestProvider.name()` | its name; use instead of `JostleProvider.PROVIDER_NAME` |
| `JslTestProvider.provider()` | the `Provider` object |
| `JslTestProvider.isFips()` | true when running against JSLFIPS |
| `JslTestProvider.has(type, alg)` | service lookup, no skip |
| `JslTestProvider.canGetCipher(transformation)` | functional probe via `Cipher.getInstance` |

**Rule: never hardcode `"JSL"` or `JostleProvider.PROVIDER_NAME` in a test.**
Both pin the run to the non-FIPS provider. The failure is silent: `fipsTest` passes while
exercising JSL. Several classes did this. They were only caught when replacing the literals made
previously "passing" FIPS tests fail.

### One provider per run

`install()` registers either JSL or JSLFIPS, never both.

Registering both breaks the FIPS run quietly. An unpinned lookup takes its key from whichever
provider sits earlier in the list. A JSL private key given to a JSLFIPS operator fails with
`private key was created by a different Jostle provider`.

### One instance per JVM

And one INSTANCE of it. A Jostle key is bound to the provider instance that created it, public
keys included, so two instances registered under the same name are not interchangeable: an
operator looked up through the second refuses the first's keys with `private key was created by a
different Jostle provider instance`.

That is easy to walk into without registering two providers. The `junit.extensions.TestSetup`
wrappers copied from bc-java call `Security.removeProvider(...)` in `tearDown`, while static key
generators - `CMSTestUtil`'s, for one - outlive the class that first built them. `install()` used
to key off `Security.getProvider(name)`, so the next class after a teardown built a fresh
`JostleProvider`, and every cached generator was then producing keys that no newly looked-up
Signature would accept. It cost 4 failures and 99 unrun tests in `pkix`, and the exception
surfaced in `JcaContentSignerBuilder.build`, nowhere near the teardown that caused it.

So `install()` now holds the instance and re-registers THAT one. Do not replace it, and do not
call `Security.addProvider(new JostleProvider())` anywhere - already forbidden for provider
selection, and now a key-lifetime bug as well.

This is not test-only: any application that re-registers the provider, or registers it in two
places, orphans the keys it made earlier.

### Naming a provider from library code

Most library code lets the JCA resolve an algorithm. A few classes cannot: a `CertificateFactory`,
a CRL or certificate `verify`, a `CertStore`, a `CertPathBuilder`, and the content encryptor a CMP
challenge is built with all take a provider name. Those sites read
`org.bouncycastle.jcajce.util.DefaultProviderName`, whose default is `"JSL"`. bc-java hardcoded its
own provider name at each of them, which cannot work here - there is no `BouncyCastleProvider` in
this fork.

The default is right for a `test` leg and wrong for a `fipsTest` leg, where only `JSLFIPS` is
registered. `JslTestProvider.install()` therefore repoints `DefaultProviderName` at whichever
provider the run installed. A test that reaches one of those sites without calling `install()`
gets a `NoSuchProviderException` naming `JSL`, usually wrapped: `PKIXCertPathReviewer` turns it
into `IllegalStateException: unable to rebuild certpath`, which says nothing about providers at
all.

This was measured, not predicted. `CheckNameConstraintsTest.testPKIXCertPathReviewer` had been
disabled since the initial checkin for exactly that wrapped message; the certificate factory site
was the cause.

**Two of the thirteen sites are covered. Treat the other eleven as unverified.** Setting the name to
a value no provider answers to leaves the whole suite green apart from those two and the core test
that asserts the default — so a wrong site would not be caught. The covered two are
`PKIXCertPathReviewer`'s certificate factory, via that test, and `SignedMailValidator`'s, via
`ProviderNameSiteTest`.

`ProviderNameSiteTest` is the pattern to copy for the rest. It drives
`SignedMailValidator.createCertPath`, which is public and static and needs only a certificate rather
than a signed message, and it asserts through the **cause chain** rather than the message, because
the validator wraps what the JCA throws. Three cells: a name no provider answers to must be
reported, `null` must resolve through the JCA default, and a control on the installed name so a
broken fixture cannot masquerade as a passing assertion.

Which site a test reaches is a question to answer by falsification, not by reading the code.
`createCertPath` touches two name-reading helpers, and the obvious guess — that the
`cert.verify(key, provider)` at :706 runs first — is wrong. Reverting each helper to a literal in
turn settles it: with both reverted the nonsense cell fails, with only the certificate factory
reverted it fails, with only `verify` reverted it passes. So that test reaches the certificate
factory and the four `verify` sites remain uncovered.

An application that registers the provider under another name must call
`DefaultProviderName.setProviderName` itself, before using the library. Setting it to `null` makes
every site fall back to JCA resolution, which takes the first installed provider serving the
algorithm.

### Raw RSA on JSLFIPS

`Signature.getInstance("NoneWithRSA", "JSLFIPS")` RESOLVES and then refuses at `initSign` and
`initVerify`, with a fallback-eligible `InvalidKeyException` carrying
`inner_evp_generic_fetch:unsupported ... Algorithm (NONE : 0)`. Identical on the 3.1.2 and 3.5.8
modules, so it is neither module- nor `fipsmodule.cnf`-dependent.

This is on purpose, and the provider says so at the registration site: JSLFIPS builds the base
`RSASignatureSpi` with digest `"NONE"`, not the `RSASignatureSpi$None` subclass JSL uses, precisely
because the module has no `NONE` digest - init fails and the non-approved raw path is never
reached. A test on that side pins it, so it will not change quietly. Contrast `NoneWithECDSA`,
which signs on both providers and both modules: a NONE digest is not refused in general, only this
registration declines to reach one.

Two consequences here:

- A `getService` hit proves nothing, and neither does `getInstance`. This is the sharpest example
  of **Prefer a functional probe**: only `canSign` separates registered from usable.
- It makes bc-java's TLS 1.3 mock servers unusable as written under JSLFIPS - they sign
  CertificateVerify with an `rsa_pkcs1` credential, which `JcaTlsRSASigner` performs through this
  name, and bc-java's own `TODO[tls13]` admits that is wrong for 1.3. `JslTls13ServerCredentials`
  probes and substitutes an ECDSA credential.

A registered-but-unusable service is worth recognising by shape, because it looks identical to a
provider defect from outside. It was reported as one; the intent was in the source, not in
`SERVICES.md`, which lists the name with nothing saying it refuses.

## What JSLFIPS can do

**The premise changed on 2026-08-19 (jar `c236fdf9`).** JSLFIPS no longer asserts any concept of
FIPS approval. Its surface is what the OpenSSL FIPS *module serves*. Whether a given use is
approved is the operator's determination, not the provider's.

Two consequences for gating:

- Do not gate on "is this approved". Gate on "does this work", probed.
- The module already labels its own algorithms (`fips=yes` / `fips=no`), so anything marked
  `fips=no` is unfetchable without any Java-side list.

**Since jar `e6f9fd00` (23 Aug 2026), one JSLFIPS build serves multiple FIPS module versions and
configurations, and its surface varies with the loaded module.** Suite verified green against
3.1.2 (CMVP cert #4985) and 3.5.7 installed `-pedantic`. Two axes of variation:

- **Module version**: X25519/X448 registration is probed at provider construction. A 3.1.2 module
  serves them; under 3.5.x they are absent and `getInstance` throws `NoSuchAlgorithmException`.
  This is the intended contract, not a bug. `JcaTlsProtocolXDHTest` handles it with its
  `supports("KeyAgreement.X25519")` probe.
- **fipsinstall configuration, not version**: most strictness lives in the module's
  `fipsmodule.cnf`. A `-pedantic` install sets `dsa-sign-disabled`, `rsa-pkcs15-pad-disabled`,
  `hmac-key-check`, `signature-digest-check` to 1; a plain install leaves them 0, so a
  default-configured 3.5.x module signs DSA and permits SHA-1 signing. **Assert the contract
  (works OR refused-typed), never one answer**, and read the cnf before calling a difference
  version-related.

Where the module declines DSA, the refusal is now typed: `generateKeyPair()` and
`AlgorithmParameterGenerator.generateParameters()` throw `ProviderException` ("DSA key generation
is not supported..."), `Signature.initSign()` throws `InvalidKeyException` ("DSA signature
generation is not supported..."). DSA key import and signature verification always work.
Previously this surfaced as an opaque `OpenSSLException` or "OpenSSL Error: null".
`CMSTestUtil.makeDsaKeyPair()` returns null on the typed refusal (the null-certificate pattern);
`canSign` probes catch it as any other `Exception`. `JostleFIPSProvider.moduleDescription()`
exists for diagnostics only — do not branch on it.

Facts below are probed against jar `e6f9fd00` with the 3.1.2 module. Re-probe rather than
trusting them.

| engine | JSLFIPS |
|---|---|
| KeyPairGenerator / KeyFactory | DH, DSA, EC, RSA, **X25519, X448 (3.1.2 module only, see above)** |
| Signature | RSA / DSA / ECDSA with SHA1, SHA2, SHA3; RSASSA-PSS; **NoneWithECDSA both directions** |
| MessageDigest | SHA1, SHA2-\*, SHA3-\*, SHAKE |
| KeyAgreement | DH, ECDH with **all** X9.63 KDF variants including SHA-1, X25519, X448 (3.1.2 only) |
| KeyGenerator | AES |
| KeyStore | **none** — see below |

**Absent**, because the module marks them `fips=no` or does not carry them: Ed25519, Ed448, DESede,
MD5, RIPEMD, SM3, BLAKE2, ARIA, Camellia, SM4, ChaCha20, Poly1305, scrypt, Argon2, all PQC
(ML-DSA, ML-KEM, SLH-DSA), OCB mode, brainpool curves.

**Present but unusable**, which a service lookup will not tell you:

- `NoneWithRSA` registers and then fails at `initSign`. The module has no "NONE" digest. RSA cannot
  sign a caller-supplied digest, which is what TLS 1.2 needs. The raw-RSA compliance question is
  with the module owner and is about approval, not exposure.
- **SHA-1 signature generation** is refused; SHA-1 *verification* works. This is the module, not an
  approval filter, and it did not change with the premise.
- **PKCS#12 is withdrawn from JSLFIPS entirely** (jar `eb072f16`). Every `PKCS12*` type throws
  `KeyStoreException`. The reason is capability, not approval: verifying the traditional PKCS#12 MAC
  needs `PKCS12KDF`, and OpenSSL registers that only in its default provider. The FIPS provider's
  KDFs are HKDF, TLS13-KDF, SSKDF, PBKDF2, SSHKDF, X963KDF, X942KDF, TLS1-PRF, KBKDF and CTR-DRBG.
  A FIPS keystore could therefore not **read** a conventional `.p12` at all — not one written by
  JSL, not one written by BouncyCastle — only RFC 9579 PBMAC1 keystores, which are rare. A service
  that fails on nearly every keystore a caller already has is worse than its absence. **Use JSL for
  keystores.** Do not re-add this on the assumption it was an approval exclusion.
- **`RSA/ECB/PKCS1Padding`** is unregistered deliberately. The module serves PKCS#1 v1.5 decrypt,
  but Jostle's implicit-rejection guard refuses to initialise without the Bleichenbacher mitigation,
  which 3.1.2 cannot provide. That is a security decision, not an approval filter.
- **Explicit DH parameters** are refused; the module generates none of its own. Initialise DH by key
  size and let it pick an approved named group.

Working as expected, do not "fix": BC's algorithm spelling resolves through aliases, so `SHA-256`,
`SHA256WITHRSA` and bare OIDs work even though the module registers `SHA2-256`. AES key wrap
resolves by name and by OID on both providers.

### RSA-PSS certificates

Fixed provider-side as of jar `2f24fb8f`. A key decoded from an `id-RSASSA-PSS` SPKI now re-encodes
as `id-RSASSA-PSS` with parameters, byte identically, on both providers.

Why it matters: BouncyCastle decides `rsa_pss_pss` support from the re-encoded key, not the
certificate bytes. `JcaTlsCertificate.getSubjectPublicKeyInfo()` is
`SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded())`. While the encoding normalised to
`rsaEncryption`, every PSS-PSS certificate was rejected.

`JcaTlsCryptoTest.testSignatures13` needs no gate now. If
`certificate_unknown(46); No support for rsa_pss_pss` returns, check that round trip first.

## Capability reporting

`JcaTlsCrypto` must report only what the provider can actually do.

Upstream answers "yes" flatly because BC's own provider carries everything. Here it may not.
Advertising a scheme we cannot perform fails mid-handshake instead of at negotiation.

Three methods were corrected:

- `hasCryptoHashAlgorithm` probes the digest. Upstream returns an unconditional `true`.
- `hasSignatureAlgorithm` probes Ed25519 and Ed448.
- `isSupportedSignatureScheme` checks the curve a TLS 1.3 ECDSA scheme pins.

**Rule: when a test fails under FIPS with `'resource' doesn't specify a valid private key` or a
handshake `internal_error`, suspect over-reporting here before gating the test.**

## Which gate to use

Gating is deliberate policy. We keep no hand-maintained list of "FIPS-relevant" classes. Such a
list rots when anyone adds a test.

**JUnit 4** — anything not extending `junit.framework.TestCase`, including `SimpleTest` subclasses
reached through an `@Test` bridge. Use assumptions. They report a real skip.

```java
JslTestProvider.assumeAlgorithm("KeyPairGenerator.ML-KEM-768");
JslTestProvider.assumeCipher("AES/OCB/NoPadding");
JslTestProvider.assumeNotFips("OCB is not an approved AEAD mode");
```

**JUnit 3** — `extends TestCase`. Assumptions do **not** skip. JUnit38ClassRunner reports
`AssumptionViolatedException` as a failure. This is the same trap that makes `@Ignore` useless
there. Return early instead.

```java
if (!JslTestProvider.supports("Signature.ED25519"))
{
    return;      // supports() logs "[skipped] ..." so it is visible
}
```

To gate a whole JUnit 3 class, override `runTest()` in the concrete subclass. It covers every
method without touching a shared base class.

```java
protected void runTest() throws Throwable
{
    if (!JslTestProvider.supports("KeyPairGenerator.ML-KEM-768")) { return; }
    super.runTest();
}
```

### Probe, do not ask isFips()

**Rule: gate on a probe of the behaviour, never on `isFips()`, wherever a probe is possible.**

A probed gate lifts by itself when the provider gains the capability. An `isFips()` gate does not,
and nothing tells you it has gone stale — the test simply keeps skipping something that works.

This was demonstrated, not theorised. When JSLFIPS gained X25519, `JcaTlsProtocolXDHTest` resumed on
its own because it gated on `supports("KeyAgreement.X25519")`. The `isFips()` gates in the same run
had to be found and converted by hand.

Use the strongest probe the question needs:

| question | use |
|---|---|
| is the service registered | `has(type, alg)` / `supports(...)` / `assumeAlgorithm(...)` |
| can this cipher transformation be built | `canGetCipher(...)` |
| can it be *initialised* | `canInitCipher(...)` |
| can this signature actually sign | `canSign(sigAlg, keyAlg, keySize)` |

`canSign` exists because registration is not usability: JSLFIPS registers `NoneWithRSA` and refuses
it at `initSign`, and refuses SHA-1 signing while serving SHA-1 verification. `canInitCipher` exists
because `Cipher.getInstance("AES/OCB/NoPadding")` succeeds and only `init` fails.

`isFips()` remains correct for genuinely structural differences — key sizes, choosing a different
digest — where there is nothing to probe.

### Probing rules

- **Mode and padding need a functional probe, not a service lookup.** Providers register the base
  algorithm (`AES`), so `getService("Cipher", "AES/OCB/NoPadding")` returns null even where OCB
  works. Gating on it would skip on JSL too. Use `assumeCipher` / `canGetCipher`.
- **`getInstance` succeeding is not proof the mode works.**
  `Cipher.getInstance("AES/OCB/NoPadding")` succeeds against JSLFIPS. The failure appears at
  `init`, when OpenSSL cannot fetch the mode. For a structurally non-approved mode, use
  `assumeNotFips("...")` with the reason.
- **Gate on observed behaviour, not on a compliance conclusion.** Probe it.

## Prefer adapting over skipping

Where the difference is a parameter rather than a missing algorithm, make the test FIPS-aware.
Coverage is worth more than convenience.

- `CMSTestUtil` signs scaffolding certificates with SHA-256 under FIPS. `SHA1withRSA` is refused
  for signature generation. The certificate is scaffolding, not the thing under test.
- RSA generators use 2048 bits under FIPS instead of 1024.
- `CMSTestUtil` initialises DH by key size under FIPS. Explicit `(p, g)` is refused; the module
  generates no DH parameters and requires an approved named group.

## Static initialisers

A missing algorithm inside a `static { }` block fails class initialisation. It takes every test in
the class down with `NoClassDefFoundError`. That is not a skip, and the message names no cause.

`CMSTestUtil` builds about 20 key-pair generators this way. They go through `optionalKpg()`, which
returns null instead of throwing. The `makeXKeyPair()` accessors return null in turn.

**Rule: any new generator added there must follow that pattern.**

## Gradle

`TEST_FIPS_LIB` must be a task input. Gradle's up-to-date check hashes task inputs, not environment
variables. A task last run without the variable is UP-TO-DATE when re-run with it set. It replays a
cached all-skipped result as `BUILD SUCCESSFUL` in milliseconds. The `openssl-jostle` repo was bitten
by this; see its `.claude/guides/testing.md` and `verify-test-matrix` skill.

Both `test` and `fipsTest` declare:

```groovy
inputs.property('fipsLib', System.getenv('TEST_FIPS_LIB') ?: '')
```

If you doubt a green run, read the result XML rather than the exit code, and use `--rerun`.

`failOnNoDiscoveredTests = false` is set. `core` has no tests of its own but still compiles the
shared support class.

## The TLS handshake matrix does not run

`TlsTestSuite` builds the full matrix from a JUnit3 `public static Test suite()` factory. It covers
SSLv3 through TLS 1.3, both crypto backends on each side, and the auth variants.

**Gradle never calls it.** `TlsTestCase` and `DTLSTestCase` each report one test, `testDummy`, whose
comment says it exists to "avoid 'No tests found' warning from junit".

So the 58 tests counted in `tls` are the unit-level classes plus the four `Jca*Protocol*` classes
(KEM, hybrid, XDH, raw keys). No end-to-end handshake runs on either provider.

This is the `SimpleTest` `@Test`-bridge trap one level up. A `suite()` factory needs
`@RunWith(AllTests.class)` or equivalent to be discovered.

Consequences:

- No TLS 1.2 ECDSA negotiation coverage. Nothing here would catch the raw `NoneWithECDSA` verify
  restriction. No gate is needed for it, precisely because no test reaches it.
- No DTLS coverage. No version-negotiation or fallback coverage. No cipher-suite matrix.

Enabling it is its own job. The matrix generates cases for GOST and SRP, which this fork
deliberately lacks. Expect to triage many generated cases rather than get a clean pass.

**Unverified claim, flagged deliberately.** The TLS 1.2 position under FIPS — `rsa_pkcs1_*` neither
direction, `ecdsa_*` sign but not verify, `rsa_pss_rsae_*` both — rests on unit probes and code
reading. No handshake has demonstrated it. Both this repo and the provider repo believe it. Treat it
as a thing to establish, not a thing established.

## Verifying a provider is really doing the work

A green suite does not prove the crypto went where you think. Two techniques do.

1. **Falsify.** Register an empty `Provider` named `JSL` before the tests run. Their own
   `addProvider` then no-ops, because the name is taken. Anything genuinely depending on JSL fails
   immediately.
2. **Count.** Same trick, but have the stand-in delegate to a real provider and tally `getService`
   calls. Two CMS classes alone made 1,230 lookups across 117 distinct services.

A test passing a provider **instance** (`setProvider(new JostleProvider())`, as the TLS tests do)
bypasses the name registry. Name-based stand-ins cannot intercept it. That is itself proof the call
reaches that object.

## Known gaps

- **Three classic CMS classes are gated wholesale under FIPS**: `NewSignedDataTest`,
  `NewEnvelopedDataTest`, `CMSAuthEnvelopedDataStreamGeneratorTest`. Their assertions rest on SHA-1
  signing, RSA PKCS#1 v1.5 key transport, DESede content encryption and Edwards/PQC signatures —
  59 failures across four causes. Narrowing to the FIPS-clean methods is unfinished.
- **JUnit 3 early returns are silent passes**, not skips. 137 tests return early under FIPS and
  count as passing. They log `[skipped] ...`, but the result XML cannot distinguish them. Treat the
  reported FIPS count as an upper bound.
- **The handshake matrix**, above.

## Reading a FIPS security policy

Two failure modes have happened repeatedly here. Both produced confident, wrong claims.

**Non-approved entries are scoped by usage, not by algorithm name.** HKDF is approved except below
112 bits. X963KDF is approved except with certain PRFs. OneStep KDF is approved except with SHAKE.
HMAC is approved except below 112 bits. The ECDSA SigVer Component carries no narrowing clause at
all. Judging by algorithm name alone is wrong about half the time.

**Accurate quotes are not a complete reading.** The provider repo owns the policy analysis; this
repo consumes it. A claim once arrived with real, correct quotes from the approved-algorithms and
approved-services tables. The non-approved tables had not been read. Both halves of the ECDSA
question were settled wrongly before Table 8 was consulted.

**Rule: do not treat a code comment in this area as evidence, on either side. Require a policy
quote, and check the non-approved tables before concluding something is approved.**
