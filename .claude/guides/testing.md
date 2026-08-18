# Testing bc-jostle-libs

How the suite is wired, and the decisions behind it. Read this before changing anything about how
tests select a provider.

## The two runs

| task | provider | when |
|---|---|---|
| `./gradlew test` | **JSL** (`JostleProvider`) | always |
| `./gradlew fipsTest` | **JSLFIPS** (`JostleFIPSProvider`) | only when `TEST_FIPS_LIB` is set |

```bash
export TEST_FIPS_LIB=/Users/meganwoods/openssl/openssls/osx_3_1_2/lib/ossl-modules/fips.dylib
./gradlew test fipsTest --continue
```

Current state: **JSL 412 tests / 0 failures / 0 skipped**, **JSLFIPS 412 tests / 0 failures**, of
which ~259 do real work against the FIPS module and the rest gate themselves out (see below).

`--continue` matters for `fipsTest`: without it Gradle stops at the first failing module and you
see a fraction of the picture.

## Provider selection goes through one class

`testsupport/src/main/java/org/bouncycastle/jsl/test/JslTestProvider.java`, compiled into **every**
module's test source set (the modules do not otherwise share test code; the root `build.gradle`
adds the directory to each `sourceSets.test`).

- `JslTestProvider.install()` — register the provider under test, idempotently
- `JslTestProvider.name()` — its name; use this instead of `JostleProvider.PROVIDER_NAME`
- `JslTestProvider.provider()` — the `Provider` object, where a test needs the instance
- `JslTestProvider.isFips()` — for behaviour that must differ (key sizes, digests)

**Never hardcode `"JSL"` or `JostleProvider.PROVIDER_NAME` in a test.** Both pin the run to the
non-FIPS provider, and the failure mode is silent: the FIPS task appears to pass while actually
exercising JSL. Several classes were doing exactly this and were only caught because replacing the
literals made previously "passing" FIPS tests start failing.

### Exactly one Jostle provider is installed per run

`install()` registers *either* JSL *or* JSLFIPS, never both. Registering both looks harmless and
quietly breaks the FIPS pass: a key generated through an unpinned lookup comes from whichever
provider sits earlier in the list, and handing a JSL private key to a JSLFIPS operator fails with
`private key was created by a different Jostle provider`. That accounted for the first batch of
FIPS failures.

## Gating, not an allow-list

The FIPS module is a much smaller surface than JSL. Tests that need something it does not implement
**gate themselves**; we deliberately do not keep a hand-maintained list of "FIPS-relevant" classes,
because such a list rots the moment anyone adds a test.

What JSLFIPS (OpenSSL 3.1.2 FIPS module) actually has:

| engine | JSLFIPS |
|---|---|
| KeyPairGenerator / KeyFactory | DH, DSA, EC, RSA — **only** |
| Signature | RSA / DSA / ECDSA × SHA1, SHA2, SHA3; RSASSA-PSS |
| MessageDigest | SHA1, SHA2-\*, SHA3-\*, SHAKE |
| KeyAgreement | DH, ECDH (+KDF variants) |
| KeyGenerator | AES |

Absent: **Ed25519/Ed448, ML-DSA, ML-KEM, X25519/X448**, ChaCha20, Argon2, MD5, RIPEMD, SM3, DESede,
Camellia, and the **brainpool curves**. Also refused by policy: **SHA-1 for signature generation**,
**RSA PKCS#1 v1.5 key transport**, and **RSA keys under 2048 bits**. `NoneWithRSA` is registered
but is a deliberate dead end (the module has no "NONE" digest), so RSA cannot sign a
caller-supplied digest — which is what TLS 1.2 needs. `NONEwithECDSA` *is* live as of the
2026-08-18 provider build.

**The SHA-1 X9.63 KDF is gone from JSLFIPS, and that reaches further than algorithm choice.** The
policy lists X963KDF with a SHA-1 PRF as not allowed, so `ECDHWITHSHA1KDF` / OID
`1.3.133.16.840.63.0.2` no longer resolve there (SHA-224 upward are unaffected). Nothing in this
repo defaults to it, and the one test that names it — `NewEnvelopedDataTest.testStaticStaticDHAgreement`
— sits inside a class already gated for FIPS, so the suite does not go red. That is an absence of
coverage, not a pass.

Two consequences worth knowing, because they are consumer-facing rather than test-facing:

- `CMSAlgorithm.ECDH_SHA1KDF` / `ECCDH_SHA1KDF`, `CMSEnvelopedGenerator.ECDH_SHA1KDF` and
  `SMIMEEnvelopedGenerator.ECDH_SHA1KDF` are **published API** here. Any caller naming one gets
  `NoSuchAlgorithmException` against JSLFIPS.
- More importantly it is not only a forward choice. `JceKeyAgreeRecipient` keeps a
  `possibleOldMessages` set (`dhSinglePass_stdDH_sha1kdf_scheme`, `mqvSinglePass_sha1kdf_scheme`)
  used on the pre-RFC 5753 fallback, so **a JSLFIPS deployment cannot decrypt archived
  enveloped-data protected with that KDF**, whatever it would choose today.

The provider's `unapproved_services=true` config key is the supported escape hatch, and its Javadoc
documents this exact recovery scenario. Enabling it does not make the operation approved — the
deployment is in non-approved mode while it is set — so the honest handling is to enable it for the
recovery, re-protect the data under an approved algorithm, and turn it off again.

**Reading a security policy: usage scope, not algorithm scope.** The module's non-approved entries
are scoped by *usage*, not by algorithm name: HKDF is approved except below 112 bits, X963KDF except
with certain PRFs, OneStep KDF except with SHAKE, HMAC except below 112 bits — while the ECDSA
SigVer Component carries no narrowing clause at all. Judging by the algorithm name gets it wrong
about half the time, which is how four confident claims went wrong here in both directions.

**The lesson for this side of the fence is about second-hand readings.** The provider repo owns the
policy analysis, and we consume it. When a JSLFIPS capability claim arrives — "X is approved", "Y is
not" — the failure mode we hit was not a claim without evidence. It came with real, accurate quotes
from the approved-algorithms and approved-services tables; they simply were not the whole picture,
because the non-approved tables had not been read yet. Accurate quotes are not the same as a
complete reading. So: gate on **observed provider behaviour** (probe it, as `JslTestProvider.has` /
`canGetCipher` do), not on a compliance conclusion, and when a gate's stated reason cites policy,
word it around the axis most likely to move — the specific curve range or key size in question
rather than a flat "non-approved" — so it reads correctly when the analysis is refined.

**RSA-PSS certificates.** These were a long-running trap and are now fixed provider-side: a key
decoded from an `id-RSASSA-PSS` SPKI re-encodes as `id-RSASSA-PSS` with its parameters, byte
identically, on both providers (as of the 2026-08-18 build, jar `2f24fb8f…`). It matters because
BouncyCastle decides `rsa_pss_pss` support from the *re-encoded key*, not the certificate bytes —
`JcaTlsCertificate.getSubjectPublicKeyInfo()` is `SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded())`
— so while the encoding normalised to `rsaEncryption`, every PSS-PSS certificate was rejected.
`JcaTlsCryptoTest.testSignatures13` needed no gate once that landed. If you see
`certificate_unknown(46); No support for rsa_pss_pss` again, check that round trip first.

**Capability reporting must be truthful, and `JcaTlsCrypto` is where that lives.** Upstream can
answer "yes" flatly because BC's own provider carries everything; here the provider may not, and
advertising a scheme we cannot perform fails mid-handshake rather than at negotiation. Three
places were corrected for this: `hasCryptoHashAlgorithm` now probes the digest instead of
returning an unconditional true, `hasSignatureAlgorithm` probes Ed25519/Ed448, and
`isSupportedSignatureScheme` checks the curve a TLS 1.3 ECDSA scheme pins. If a test fails under
FIPS with "resource doesn't specify a valid private key" or a handshake `internal_error`, suspect
over-reporting here before gating the test.

Separately, and *not* FIPS-specific: AES key wrap resolves only by OID on **both** providers —
`AESWrap`, `AESWRAP`, `AESKW`, `AES/KW/NoPadding` and the padded variants all fail on JSL as well.
BC's CMS path wraps by OID, so it has not bitten us.

Good news: BC's algorithm spelling works. `SHA-256`, `SHA256WITHRSA` and bare OIDs all resolve
through aliases even though the module registers `SHA2-256`.

### Which gate to use

**JUnit 4 tests** (anything not extending `junit.framework.TestCase` — including `SimpleTest`
subclasses reached through an `@Test` bridge) — use the assumption form, which reports a real skip:

```java
JslTestProvider.assumeAlgorithm("KeyPairGenerator.ML-KEM-768");
JslTestProvider.assumeCipher("AES/OCB/NoPadding");   // mode/padding: see below
```

**JUnit 3 tests** (`extends TestCase`) — an assumption does **not** skip there. JUnit38ClassRunner
reports `AssumptionViolatedException` as a **failure**, the same trap that makes `@Ignore` useless
in these classes. Return early instead:

```java
if (!JslTestProvider.supports("Signature.ED25519"))
{
    return;      // supports() logs "[skipped] ..." so it is visible in the output
}
```

To gate a whole JUnit 3 class, override `runTest()` in the concrete subclass — it covers every
method without touching the shared base class:

```java
protected void runTest() throws Throwable
{
    if (!JslTestProvider.supports("KeyPairGenerator.ML-KEM-768")) { return; }
    super.runTest();
}
```

**Mode/padding support needs a functional probe, not a service lookup.** Providers register the base
algorithm (`AES`), so `getService("Cipher", "AES/OCB/NoPadding")` is null even where OCB works
fine — gating on it would skip on JSL too. Use `assumeCipher` / `canGetCipher`, which call
`Cipher.getInstance`.

**And even `getInstance` is not proof the mode works.** `Cipher.getInstance("AES/OCB/NoPadding")`
*succeeds* against JSLFIPS — the mode string is accepted — and the failure only surfaces at
`init`, when OpenSSL cannot fetch the mode from the FIPS provider. Where a mode is structurally
non-approved (OCB), gate on `assumeNotFips("...")` with the reason rather than trying to detect
it.

### Prefer adapting over skipping

Where the difference is a *parameter* rather than a missing algorithm, make the test FIPS-aware
instead of skipping it — the coverage is worth more than the convenience:

- `CMSTestUtil` signs its scaffolding certificates with SHA-256 under FIPS (`SHA1withRSA` is
  refused for signature generation). The certificate is scaffolding, not the thing under test.
- RSA generators use 2048 bits under FIPS instead of 1024.

### Static initialisers are the sharp edge

A missing algorithm inside a `static { }` block fails class initialisation and takes **every** test
in the class down with `NoClassDefFoundError` — not a skip, and the message names none of the real
cause. `CMSTestUtil` builds ~20 key-pair generators this way; they go through `optionalKpg()`, which
returns null rather than throwing, and the `makeXKeyPair()` accessors return null in turn. Any new
generator added there must follow the same pattern.

## Gradle: TEST_FIPS_LIB must be a task input

Gradle's up-to-date check hashes task inputs — **not environment variables**. A test task that last
ran without `TEST_FIPS_LIB` is considered UP-TO-DATE when re-run with it set, and replays the cached
result as `BUILD SUCCESSFUL` in milliseconds while the FIPS tests never execute. This bit the
`openssl-jostle` repo (see its `.claude/guides/testing.md` and `verify-test-matrix` skill).

Both `test` and `fipsTest` therefore declare:

```groovy
inputs.property('fipsLib', System.getenv('TEST_FIPS_LIB') ?: '')
```

so toggling the variable invalidates the task properly. If you ever doubt a green run, check the
result XML rather than the exit code, and use `--rerun`.

`failOnNoDiscoveredTests = false` is set because `core` has no tests of its own but still compiles
the shared support class.

## The TLS handshake matrix does not run at all

`TlsTestSuite` builds the full matrix — SSLv3 through TLS 1.3, both crypto backends on each side,
the auth variants — from a JUnit3 `public static Test suite()` factory. **Gradle never calls it.**
`TlsTestCase` and `DTLSTestCase` each report exactly one test, `testDummy`, whose own comment says
it exists to "avoid 'No tests found' warning from junit". So the 58 tests counted in `tls` are the
unit-level classes plus the four `Jca*Protocol*` classes (KEM, hybrid, XDH, raw keys), and **no
end-to-end handshake is exercised on either provider**.

This is the same family of trap as `SimpleTest` needing an `@Test` bridge, one level up: a
`suite()` factory needs `@RunWith(AllTests.class)` (or equivalent) to be discovered.

Consequences to keep in mind before trusting a green tls run:

- There is **no TLS 1.2 ECDSA negotiation coverage**, so nothing in this repo would catch the raw
  `NoneWithECDSA` verification being refused under FIPS. That behaviour is real — probed directly —
  but our suite is silent on it, and no gate is needed precisely because no test reaches it.
- There is no DTLS coverage, no version-negotiation or fallback coverage, and no cipher-suite matrix.

Lighting it up is worthwhile but is its own piece of work: the matrix covers algorithms this fork
deliberately lacks (GOST, SRP, and so on), so expect to gate or drop a large number of generated
cases rather than a clean pass.

**And note what that means for what we currently claim.** The TLS 1.2 position under FIPS —
`rsa_pkcs1_*` neither direction, `ecdsa_*` sign but not verify, `rsa_pss_rsae_*` both — rests on
unit-level probes and code reading, not on a handshake. It is believed on both sides of the fence
and nobody has watched it happen. Confirming that table is one of the first things enabling the
matrix would buy, so treat it as a thing to establish rather than a thing already established.

## Known gaps / follow-up

- **Three classic CMS classes are gated wholesale under FIPS**: `NewSignedDataTest`,
  `NewEnvelopedDataTest`, `CMSAuthEnvelopedDataStreamGeneratorTest`. Most of what they assert rests
  on SHA-1 signing, RSA PKCS#1 v1.5 key transport, DESede content encryption and Edwards/PQC
  signatures — 59 individual failures across four root causes. Narrowing these to the methods that
  are genuinely FIPS-clean is worthwhile and unfinished.
- **JUnit 3 early-returns are silent passes**, not skips: 137 tests return early under FIPS and are
  counted as passing. They log `[skipped] ...`, but the XML cannot distinguish them. Treat the
  reported FIPS count as an upper bound; ~259 tests do real work.
- **`AESWrap` is missing from JSLFIPS** — provider-side, worth raising with `../openssl-jostle`
  alongside the EAX gap.

## Verifying a provider is really doing the work

A green suite does not prove the crypto went where you think. Two techniques that do:

1. **Falsify** — register an empty `Provider` named `JSL` *before* the tests run (their own
   `addProvider` then no-ops, since the name is taken). Anything genuinely depending on JSL fails
   immediately.
2. **Count** — same trick, but have the stand-in delegate to a real provider and tally
   `getService` calls. Two CMS classes alone made 1,230 lookups across 117 distinct services.

Note that a test passing a **provider instance** (`setProvider(new JostleProvider())`, as the TLS
tests do) bypasses the name registry entirely, so name-based stand-ins cannot intercept it — which
is itself proof that the call reaches that object.
