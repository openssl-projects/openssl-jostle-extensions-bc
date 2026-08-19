# Testing bc-jostle-libs

Reference for how the test suite selects a crypto provider, and what each provider can do.
Read before changing provider selection, adding a FIPS gate, or trusting a green run.

## Symptom index

Match the error first. Each row gives the cause and the action.

| symptom | cause | action |
|---|---|---|
| `no such algorithm: <X> for provider JSLFIPS` | FIPS module lacks `<X>` | Gate the test. See **Which gate to use**. |
| `KeyStore.store` fails on JSLFIPS with a bare `PKCS12` keystore | traditional PKCS#12 MAC needs `PKCS12KDF`, which the FIPS provider does not have | Use `PKCS12-PBMAC1` explicitly. It uses PBKDF2 and interoperates with JSL both ways. |
| `InvalidKeyException` from `initSign` naming `digest not allowed` | SHA-1 signature *generation* refused (verification is allowed) | Sign with SHA-256. See **Prefer adapting over skipping**. |
| `RSA key size 1024 is out of range [2048, 16384]` | FIPS minimum modulus | Use 2048 under FIPS. |
| `padding PKCS1Padding not supported` | RSA PKCS#1 v1.5 key transport not approved | Gate. No workaround. |
| `certificate_unknown(46); No support for rsa_pss_pss` | SPKI `AlgorithmIdentifier` lost in key re-derivation | Check the round trip. Fixed provider-side; see **RSA-PSS certificates**. |
| `'resource' doesn't specify a valid private key` under FIPS | `JcaTlsCrypto` advertised a scheme the provider cannot do | Fix capability reporting, do not gate. See **Capability reporting**. |
| handshake `internal_error(80)` under FIPS | Same as above | Same as above. |
| `NoClassDefFoundError` on a whole test class | Missing algorithm inside a `static { }` block | See **Static initialisers**. |
| `AssumptionViolatedException` reported as a failure | Class extends `junit.framework.TestCase` | Use an early `return`, not an assumption. |
| `private key was created by a different Jostle provider` | Both Jostle providers registered at once | Only one is installed per run. See **One provider per run**. |
| FIPS suite passes in milliseconds | Gradle replayed a cached result | `TEST_FIPS_LIB` must be a task input. See **Gradle**. |

## The two runs

| task | provider | when |
|---|---|---|
| `./gradlew test` | JSL (`JostleProvider`) | always |
| `./gradlew fipsTest` | JSLFIPS (`JostleFIPSProvider`) | only when `TEST_FIPS_LIB` is set |

```bash
export TEST_FIPS_LIB=/Users/meganwoods/openssl/openssls/osx_3_1_2/lib/ossl-modules/fips.dylib
./gradlew test fipsTest --continue
```

Current state: JSL 412 tests / 0 failures. JSLFIPS 412 tests / 0 failures.
About 259 of the FIPS tests do real work. The rest gate themselves out.

Use `--continue` for `fipsTest`. Without it Gradle stops at the first failing module.

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

## What JSLFIPS can do

**The premise changed on 2026-08-19 (jar `c236fdf9`).** JSLFIPS no longer asserts any concept of
FIPS approval. Its surface is what the OpenSSL FIPS *module serves*. Whether a given use is
approved is the operator's determination, not the provider's.

Two consequences for gating:

- Do not gate on "is this approved". Gate on "does this work", probed.
- The module already labels its own algorithms (`fips=yes` / `fips=no`), so anything marked
  `fips=no` is unfetchable without any Java-side list.

Facts below are probed against jar `c236fdf9`. Re-probe rather than trusting them.

| engine | JSLFIPS |
|---|---|
| KeyPairGenerator / KeyFactory | DH, DSA, EC, RSA, **X25519, X448** |
| Signature | RSA / DSA / ECDSA with SHA1, SHA2, SHA3; RSASSA-PSS; **NoneWithECDSA both directions** |
| MessageDigest | SHA1, SHA2-\*, SHA3-\*, SHAKE |
| KeyAgreement | DH, ECDH with **all** X9.63 KDF variants including SHA-1, X25519, X448 |
| KeyGenerator | AES |
| KeyStore | PKCS12, PKCS12-PBMAC1, PKCS12-AES256-AES128, PKCS12-3DES-3DES |

**Absent**, because the module marks them `fips=no` or does not carry them: Ed25519, Ed448, DESede,
MD5, RIPEMD, SM3, BLAKE2, ARIA, Camellia, SM4, ChaCha20, Poly1305, scrypt, Argon2, all PQC
(ML-DSA, ML-KEM, SLH-DSA), OCB mode, brainpool curves.

**Present but unusable**, which a service lookup will not tell you:

- `NoneWithRSA` registers and then fails at `initSign`. The module has no "NONE" digest. RSA cannot
  sign a caller-supplied digest, which is what TLS 1.2 needs. The raw-RSA compliance question is
  with the module owner and is about approval, not exposure.
- **SHA-1 signature generation** is refused; SHA-1 *verification* works. This is the module, not an
  approval filter, and it did not change with the premise.
- Bare **`PKCS12`** keystores resolve and then fail at `store`. The traditional PKCS#12 MAC needs
  `PKCS12KDF`, which OpenSSL registers only in its default provider. Use **`PKCS12-PBMAC1`**, which
  uses PBKDF2 and interoperates with JSL in both directions.
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
