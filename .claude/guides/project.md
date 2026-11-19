# bc-jostle-libs: orientation

What this repository is, where things live, and how to build it.
Read this first. Then `testing.md` before running tests, `conventions.md` before editing.

## What it is

BouncyCastle satellite libraries rebuilt from bc-java. They keep BC's high-level APIs. They
delegate every cryptographic primitive to the **OpenSSL Jostle ("JSL") JCA provider** instead of
BC's own software crypto.

Version `1.87.1-SNAPSHOT`, tracking bc-java 1.87. A release build takes its version from a git tag:
`-PreleaseTag=v1.86.1` or bc-java's `r1rv86` (see `checkReleaseTags` for the grammar).

| module | artifact | contents |
|---|---|---|
| `core` | `bccore-jsl` | minimized bc-java core: ASN.1, util, math, support |
| `util` | `bcutil-jsl` | extended ASN.1 (CMS, CMP, CRMF, TSP, EST), OER, CBOR/C509 |
| `pkix` | `bcpkix-jsl` | certificates, CMS, CMC, TSP, PKCS, operators, PEM |
| `mail` | `bcmail-jsl` | S/MIME |
| `pg` | `bcpg-jsl` | OpenPGP |
| `tls` | `bctls-jsl` | (D)TLS and the JSSE provider |

Dependency graph: `core ← util ← pkix ← {mail, tls}`, and `pg ← util`.

## Locations

| what | where |
|---|---|
| upstream bc-java | `/Users/meganwoods/cw/bc/bc-java` (branch `main`) |
| the JSL provider source | `../openssl-jostle` — a **separate repo** |
| the provider, as consumed here | `org.openssl.jostle:openssl-jostle:${jostleVersion}:<arch>` from Maven Central |
| AI-facing docs | `.claude/guides/`, `.claude/skills/` |

**Rule: never fix a provider bug from this repo.** Report it to `../openssl-jostle`. Do not edit
that repo or hand-patch the provider jar.

**Rule: the provider jar is resolved from Maven Central by architecture.** Jostle publishes a
pom-only umbrella plus one jar per architecture (`aarch64`, `x86_64`). The root build picks the
classifier from `os.arch` and resolves it in the root project's context, because Gradle refuses a
resolution started from a subproject. `-PjostleClassifier=<arch>` overrides the detection.
`-PjostleJar=<path>` uses a local provider build instead. `jostleVersion` alone is the POM
dependency version.

## Build

```bash
./gradlew assemble    # all *-jsl jars, release 8, default JDK 17
./gradlew test        # tests against JSL
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
| container-only `CompositePrivateKey` / `CompositePublicKey` | core `jcajce` | upstream's classes encode through the BouncyCastle provider's key factories; here they only hold the two component keys of an RFC 9980 OpenPGP key |
| reduced `ConstraintUtils` | core `crypto.constraints` | upstream's tests for many lightweight parameter classes, several of them software crypto; here it knows RSA, DSA and DH parameters and the service names |
| a null `Provider` means the default search order | pg `OperatorUtils.providerHelper` and the operators that use it | `JcaOpenPGPImplementation()` passes null, and upstream's `ProviderJcaJceHelper` refuses it once a certificate's self-signatures are verified at parse |
| DTLS 1.3 record number mask through the provider | tls `JceChaCha20RecordNumberMask` | upstream uses its software ChaCha20 engine; here it is JSL's `ChaCha20` with `ChaCha20CounterParameterSpec` |
| `withNoKdf()` on both KEM specs, through Jostle's spec builders | tls `KemUtil` | Jostle's KEM spec builders start with a KDF, which TLS must not apply |
| no random passed to ML-KEM key generation, in the capability probe or the handshake | tls `KemUtil` | JSL refuses a random weaker than ML-KEM-768/1024 need, and the JDK default on Windows is such a random. The application's random is not used for ML-KEM key generation in TLS on JSL; upstream passes the crypto's |
| no default random, and none passed to the post-quantum generators unless the caller set one | pg `JcaPGPKeyPairGeneratorProvider` | as above, for ML-DSA, SLH-DSA and ML-KEM; upstream defaults to `CryptoServicesRegistrar.getSecureRandom()` |
| no default random handed to the builders | pg `JcaOpenPGPImplementation`, `JcaOpenPGPApi`, `JcaOpenPGPKeyGenerator` | as above; a builder left without one uses its own default, and the post-quantum key generation and ML-KEM encryption get none. Upstream supplies `CryptoServicesRegistrar.getSecureRandom()` or `new SecureRandom()` |
| default provider named when one is set | pkix `JcaC509CertificateConverter` | the fork's lint refuses an unqualified service lookup in production code |
| capability probing in `JcaTlsCrypto` | `hasCryptoHashAlgorithm`, `hasSignatureAlgorithm`, `isSupportedSignatureScheme` | upstream answers "yes" flatly; here the provider may lack the digest, algorithm or curve |

## Resync state

**Last resynced to bc-java `dd1e61c26066d0793d3f348bf6b4d9b73b701e77` = tag `r1rv87` (2026-11-12).**
That commit is the floor for the next resync; the one before it was `r1rv86`
(`eacda831fbe15b272933e40841d8b0827b556fae`, 2026-09-11). The work was done at `00dbc69e76`, four
commits before the tag; none of the four touches a file under the mapped trees.

**The fork's main sources are fully at 1.87.** Measured floor-independently: every `.java` under the
mapped main trees was compared against the relocated text of `r1rv87` directly. The identical, the
differing and the fork-only sets are listed in
`reviews/resync-1.87-2026-11-10/census-r1rv87/main-vs-r1rv87.tsv`.

The differences are the fork's adaptations: the provider and JSSE names, Jostle's own spec classes,
the default-provider idiom, the removed GOST and software-crypto branches, and the divergences in
the table above.

### The 1.86 move, kept for its method

At `r1rv86` the same floor-independent comparison showed the main sources fully at 1.86, and every
difference was deliberate: adaptations by blob history, plus the two files under trap 3 below. Its
record is `reviews/RESYNC-PLAN-2026-09-17.md`.

The windowed view (the upstream files changed between the floor and the target) is how the work is
FOUND, and is a subset — never quote it as the comparison. In the 1.86 move most of those files do
not exist here (pruned crypto, pqc, `jce.provider`, the `Bc*` builders), most of the rest were
already identical, and of the few that differed most did so mechanically. Most of the "hand-merge"
files and every upstream-changed test needed nothing at all; that is the shape to expect, not an
anomaly.

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
Doing it that way in the 1.86 move reported well under half of the files that really differed.

Then classify each differing file by whether its exact bytes appear anywhere in upstream's history
for that path (the `port-from-bc-java` skill, and memory `bc-java-resync-blob-history-method`), and
ask three questions in order:

1. **Did upstream MOVE the file since the floor?** If not, the difference is purely ours and there
   is nothing to take. Getting this wrong turns a merge of a few files into one of hundreds.
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

- Whether any of the upstream files absent here should now be CARRIED rather than stay pruned.
  That is a scope decision, Megan's, and no resync answers it.
- The legacy PKCS#12 PBE MAC is a provider gap, not a fork one: JSL registers no `Mac` under a
  digest OID, which is what `JcePKCS12MacCalculatorBuilder` looks up. Filed in `provider-gaps.md`
  and raised against the provider repo.

An import-based dependency check is not enough. It cannot see **same-package** references, and it
passed two files clean that the compiler then rejected. Grep the upstream file for unqualified type
names in its own package before taking it.

## Current state

- One JSLFIPS number means nothing without saying which module produced it, and a test count means
  little without the silent-skip count beside it - see `testing.md`.
- Work happens on `main`. Branch `resync-1.86` is a stale pointer at `origin/main` and carries none
  of the resync above; do not treat it as the resync branch.
- The TLS handshake matrix has never run. See `testing.md`.
