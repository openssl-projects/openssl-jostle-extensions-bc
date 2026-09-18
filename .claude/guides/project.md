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
./gradlew test        # 525 tests against JSL
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

## Resync state

**Last resynced to bc-java `eacda831fbe15b272933e40841d8b0827b556fae` = tag `r1rv86` (2026-09-11).**
That commit is the floor for the next resync; the one before it was `8a04208b` (2026-09-08).
At `r1rv86` the tag and upstream's head are the same commit.

**The fork's main sources are fully at 1.86.** Measured floor-independently, every `.java` under the
mapped main trees compared against `r1rv86` directly:

| | files |
|---|---|
| compared | 2849 |
| identical to `r1rv86` | 2714 |
| differing | 88 |
| fork-only, no upstream counterpart at that path | 47 |

All 88 differences are deliberate. 86 are adaptations by blob history; the other two are covered
under trap 3 below.

The windowed view below is how the work was FOUND, and is a subset — never quote it as the
comparison: of 482 upstream files changed between the floor and `r1rv86` in the mapped trees, 366
do not exist here (pruned crypto, pqc, `jce.provider`, the `Bc*` builders), 81 were already
identical, and 35 differed — 26 mechanically, 9 carrying adaptations. The work that came out of it
was 25 files taken verbatim, the JSSE provider pair, and one security fix. Seven of the nine
"hand-merge" files and seven of seven upstream-changed tests needed nothing at all; that is the
shape to expect, not an anomaly.

This line lives here, in a tracked file, on purpose. It used to live only in `reviews/gate-audit.md`,
which is gitignored, and that file lagged the tree three times in one day — a stale test count, a
list of reason comments that had already been written, and six fixture tests recorded as outstanding
after they had been done. **Before scheduling any item from an audit or plan file, grep the tree for
it first.**

**The JSSE provider file is no longer held.** `tls/.../jsse/provider/BouncyCastleJsseProvider.java`
was kept back from earlier resyncs because upstream's version bumps `PROVIDER_VERSION` to 1.0025 /
"Version 1.0.25" (bc-java `35e8ebf0c9`, "Move to the 1.86 release"), which advertises this fork's own
shipped JSSE provider as 1.0.25 — a release decision rather than a resync step. Megan took it with
the 1.86 move: the fork carries upstream's 1.86 JSSE code, so it reports upstream's number. The file
is now byte-equal to upstream again, along with the `ProviderInfoSuffix` seam it needs, so both
classify as mechanical for every future resync instead of becoming a permanent hand-merge.

Method. **Compare against the target tag directly, then use the window to explain what you find.**
Filtering by the upstream change window FIRST hides exactly the files nobody is looking at: a file
this fork diverges on whose last upstream change predates the floor is invisible to a windowed scan.
Doing it that way here reported 35 differing files when the real number was 88.

Then classify each differing file by whether its exact bytes appear anywhere in upstream's history
for that path (the `port-from-bc-java` skill, and memory `bc-java-resync-blob-history-method`), and
ask three questions in order:

1. **Did upstream MOVE the file since the floor?** If not, the difference is purely ours and there
   is nothing to take. Getting this wrong turns a nine-file merge into a 217-file one.
2. **Does the fork LACK any of upstream's changes?** Differing is not the same as being behind. A
   file can carry an adaptation, so classify as needing a hand-merge, and already be complete. Seven
   of nine did exactly that in the 1.86 move.
3. **Would upstream's version COMPILE here?** A blob match against OLD upstream text does not prove
   the fork is behind; it can mean the fork deliberately holds that form.
   Worked example: `core/.../crypto/util/ScryptConfig.java` and
   `core/.../jcajce/spec/XDHParameterSpec.java` each differ from `r1rv86` by one import —
   `org.bouncycastle.jsl.asn1.{misc,edec}` here, `org.bouncycastle.internal.asn1.{misc,edec}` upstream.
   Blob history calls both "behind" because the fork's line matches upstream's text from before
   `fa9f381d5d` (2024-03-08, "move of ASN.1 edec, misc, nsri and rosstandart to util package"), the
   commit that created the internal copies. This fork has no `org.bouncycastle.internal` package
   under any module, so upstream's import would not compile. They are adaptations, not gaps.

Two follow-ups out of the 1.86 move, neither a resync question:

- Whether any of the 366 upstream files absent here should now be CARRIED rather than stay pruned.
  That is a scope decision, Megan's, and no resync answers it.
- The legacy PKCS#12 PBE MAC is a provider gap, not a fork one: JSL registers no `Mac` under a
  digest OID, which is what `JcePKCS12MacCalculatorBuilder` looks up. Filed in `provider-gaps.md`
  and raised against the provider repo.

An import-based dependency check is not enough. It cannot see **same-package** references, and it
passed two files clean that the compiler then rejected. Grep the upstream file for unqualified type
names in its own package before taking it.

## Current state

- All three legs green against jar `f74cadcf` (openssl-jostle `8d8cf1e`): 525 tests and 0 failures
  on each. JSL gates 4 executions; JSLFIPS reports 5 skips and gates 74 more silently on a 3.5.8
  module, 16 and 115 on a 3.1.2 one. One JSLFIPS number means nothing without saying which module
  produced it, and a test count means little without the silent-skip count beside it - see
  `testing.md`.
- Work happens on `main`. Branch `resync-1.86` is a stale pointer at `origin/main` and carries none
  of the resync above; do not treat it as the resync branch.
- The TLS handshake matrix has never run. See `testing.md`.
