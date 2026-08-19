# bc-jostle-libs: orientation

What this repository is, where things live, and how to build it.
Read this first. Then `testing.md` before running tests, `conventions.md` before editing.

## What it is

BouncyCastle satellite libraries rebuilt from bc-java. They keep BC's high-level APIs. They
delegate every cryptographic primitive to the **OpenSSL Jostle ("JSL") JCA provider** instead of
BC's own software crypto.

Version `1.86.0-SNAPSHOT`, tracking bc-java 1.86.

| module | artifact | main | test | contents |
|---|---|---|---|---|
| `core` | `bccore-jsl` | 728 | 0 | minimized bc-java core: ASN.1, util, math, support |
| `util` | `bcutil-jsl` | 570 | 76 | extended ASN.1 (CMS, CMP, CRMF, TSP, EST), OER, CBOR/C509 |
| `pkix` | `bcpkix-jsl` | 744 | 80 | certificates, CMS, CMC, TSP, PKCS, operators, PEM |
| `mail` | `bcmail-jsl` | 51 | 6 | S/MIME |
| `pg` | `bcpg-jsl` | 324 | 35 | OpenPGP |
| `tls` | `bctls-jsl` | 426 | 80 | (D)TLS and the JSSE provider |

Dependency graph: `core ← util ← pkix ← {mail, tls}`, and `pg ← util`.

## Locations

| what | where |
|---|---|
| upstream bc-java | `/Users/meganwoods/cw/bc/bc-java` (branch `main`) |
| the JSL provider source | `../openssl-jostle` — a **separate repo** |
| the provider, as consumed here | `libs/openssl-jostle-${jostleVersion}.jar`, prebuilt |
| AI-facing docs | `.claude/guides/`, `.claude/skills/` |

**Rule: never fix a provider bug from this repo.** Report it to `../openssl-jostle`. Do not edit
that repo or hand-patch `libs/*.jar`.

**Rule: `jostleVersion` in `gradle.properties` must match the jar filename in `libs/`.** A mismatch
makes `jostleProviderJar()` resolve to a missing file. The provider then drops off the classpath
silently and test compiles fail with `package org.openssl.jostle... does not exist`. A `clean` may
be needed before the failure appears.

## Build

```bash
./gradlew assemble    # all *-jsl jars, release 8, default JDK 17
./gradlew test        # 412 tests against JSL
./gradlew fipsTest    # the same tests against JSLFIPS; needs TEST_FIPS_LIB
```

JDK toolchains come from `BC_JDK8`, `BC_JDK11`, `BC_JDK17`, `BC_JDK21`, `BC_JDK25`.
All modules compile with `options.release = 8`. Java 9+ APIs need reflection; see
`JcaNonceGenerator` for the pattern.

Tests are JUnit 4.13.2. Most migrated bc-java tests are JUnit3 style (`extends TestCase`).
That distinction matters constantly — see `testing.md`.

Each main jar is an OSGi bundle built by `biz.aQute.bnd.builder`. The root `build.gradle` sets
`Bundle-*` headers and the per-module `Export-Package` patterns (`osgiExports`). `bundle_version`
is the OSGi-legal form of `version`.

## What `core` is

`core` is not a full `bcprov`. It was reduced to what the satellites and JSL actually reach, then
stripped of algorithm implementations entirely.

Absent from `core`:

- `org.bouncycastle.jce.provider.*` — so **no `BouncyCastleProvider`**
- `pqc.*` — JSL owns post-quantum
- the `BcXXX` (`*.bc.*`) operator and cert builders
- **every cryptographic transformation**: `crypto.engines`, `crypto.digests`, `crypto.macs`,
  `crypto.generators`, `crypto.prng`, `crypto.prng.drbg`

What survives under `crypto.*` is interfaces (`Digest`, `CipherParameters`), parameter and config
holders (`params.*`, `util.PBKDF2Config`) and `CryptoServicesRegistrar` plumbing. No algorithm is
implemented in this repo.

EC curve arithmetic under `math.ec` does remain. It is reached from `asn1.x9.ECNamedCurveTable`,
which pkix needs for certificates and CSRs. Removing it means re-homing that first.

`jcajce` is the JCA seam and is load-bearing. About half of it was unreachable and was removed. The
remaining half — `JcaJceHelper` and friends, the PKIX cert-store types, the algorithm parameter
specs JSL consumes, the PBE key types, `jcajce.io` — cannot go without re-homing them.

## Deliberate divergences from bc-java

These compile cleanly if reverted and then fail at runtime. Do not "restore" them from upstream.

| divergence | where | why |
|---|---|---|
| `JostleProvider.PROVIDER_NAME`, never `"BC"` | everywhere | no `BouncyCastleProvider` exists here |
| AAD via `JceAEADCipherUtil` / `updateAAD` | pg `JcePBEProtectionRemoverFactory`, `JcePBEKeyEncryptionMethodGenerator` | JSL's OpenSSL ciphers ignore `AEADParameterSpec`'s associated-data field, so the tag is computed without the AAD |
| `(Provider)null` for the default | pg `JcaOpenPGPImplementation` | `BouncyCastleProvider` does not exist |
| throwing stubs for EC generation | pg `JcaPGPKeyPairGeneratorProvider.generateEC*` | classic EC keygen is out of scope for JSL there |
| local RFC 7748/8032 size constants | pg `JcaPGPKeyConverter` | replaces `math.ec.rfc8032.Ed25519` and friends, which are software crypto |
| `GCMParameterSpec` + `updateAAD` | tls `JceAEADCipherImpl` | JSL exposes no `AlgorithmParameters` for GCM/CCM |
| `PGPS2KCalculator` seam for Argon2 | pg `PGPUtil`, `JcePGPS2KCalculator` | routes Argon2 to `SecretKeyFactory`, so `Argon2BytesGenerator` and Blake2b could be deleted |
| public OID classes in `core`, not `internal.asn1` | `asn1.misc`, `edec`, `gnu`, `iso`, `oiw`, `cryptlib`, `rosstandart`, `iana` | upstream splits these; this fork keeps one public copy |
| capability probing in `JcaTlsCrypto` | `hasCryptoHashAlgorithm`, `hasSignatureAlgorithm`, `isSupportedSignatureScheme` | upstream answers "yes" flatly; here the provider may lack the digest, algorithm or curve |

## Current state

- Both suites green: JSL 412 / 0 failures, JSLFIPS 412 / 0 failures.
- Branch `resync-1.86` carries the 1.86 resync and the FIPS test work. Unmerged.
- The TLS handshake matrix has never run. See `testing.md`.
