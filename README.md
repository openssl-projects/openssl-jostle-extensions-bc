# bc-jostle-libs

BouncyCastle extension libraries (CMS/PKIX, S/MIME mail, OpenPGP, TLS), rebuilt
from [bc-java](https://github.com/bcgit/bc-java) to run against the **OpenSSL
Jostle ("JSL") JCA provider** instead of BouncyCastle's own software crypto.

The libraries keep BC's familiar high-level APIs (`org.bouncycastle.asn1`,
`operator`, `cert`, `cms`, `mail`, `openpgp`, `tls`, …) but delegate all
primitive cryptography — ciphers, signatures, KEMs, digests, RNG — to OpenSSL
through the JSL provider via standard JCA/JCE.

## Modules

| Module | Artifact            | Contents                                                                 |
|--------|---------------------|--------------------------------------------------------------------------|
| `core` | `bccore-jsl`        | Minimized bc-java core: ASN.1, util, and supporting classes (see below)  |
| `util` | `bcutil-jsl`        | Extended ASN.1 modules (CMS, CMP, CRMF, TSP, EST, …) and OER             |
| `pkix` | `bcpkix-jsl`        | Certificates, CMS, CMC, TSP, PKCS, operators, OpenSSL PEM support        |
| `mail` | `bcmail-jsl`        | S/MIME (JavaMail integration)                                            |
| `pg`   | `bcpg-jsl`          | OpenPGP                                                                  |
| `tls`  | `bctls-jsl`         | (D)TLS and the JSSE provider                                             |

### The minimized `core`

`core` is **not** a full `bcprov`. It has been pruned to the closure of classes
the satellite libraries and the JSL provider actually reach, and then stripped of
algorithm implementations entirely: `crypto.engines`, `crypto.digests`,
`crypto.macs`, `crypto.generators` and `crypto.prng` are all gone, along with
`pqc.*`, `jce.provider.*` and the `BcXXX` builders. What remains under `crypto.*`
is interfaces, parameter and config holders, and registrar plumbing — no algorithm
is implemented here. Every cryptographic service goes through the JSL provider.

JSL supplies the actual algorithms: AES (including GCM and RFC 3394/5649 key
wrap), RSA, EC, EdDSA, ML-DSA, SLH-DSA, ML-KEM (including the CMS
KEMRecipientInfo path of RFC 9629), SHA-2/SHA-3, HMAC, and secure random.

## The JSL provider

The provider itself lives in a separate repository, `openssl-jostle`
(`org.openssl.jostle.*`, provider name `"JSL"`, provider class
`org.openssl.jostle.jcajce.provider.JostleProvider`). It is consumed here as a
prebuilt jar:

```
libs/openssl-jostle-<jostleVersion>.jar
```

with `jostleVersion` pinned in `gradle.properties`. The version in
`gradle.properties` **must** match the jar filename in `libs/`, otherwise the
provider silently drops off the compile/test classpath.

Typical usage:

```java
import java.security.Security;
import org.openssl.jostle.jcajce.provider.JostleProvider;

Security.addProvider(new JostleProvider());

// then pass JostleProvider.PROVIDER_NAME ("JSL") wherever bc-java
// examples use "BC", e.g.:
new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider(JostleProvider.PROVIDER_NAME)
        .build(privateKey);
```

## Building

Requirements: Gradle (wrapper included) and JDK toolchains supplied via the
`BC_JDK8` / `BC_JDK11` / `BC_JDK17` / `BC_JDK21` / `BC_JDK25` environment
variables (see `gradle.properties`). Sources are compiled with `--release 8`.

```bash
./gradlew assemble          # build all *-jsl jars
./gradlew test              # run the suite against JSL (412 tests; core has none)
./gradlew fipsTest          # run the same suite against JSLFIPS

# run a single test set
./gradlew :pkix:test --tests "org.bouncycastle.jsl.test.*" --rerun-tasks
```

Each module produces `bcXxx-jsl-<version>.jar` plus `-sources` and `-javadoc`
jars. The main jar is an OSGi bundle (built with the bnd plugin): per-module
`Export-Package` headers mirror the matching bc-java module, and
`Import-Package` carries a versioned range `[bundle_version, maxVersion)` on
`org.bouncycastle.*`.

## Tests

Tests are migrated from bc-java (also an ongoing effort). They run under JUnit 4.13.2,
though most are JUnit3-style (`extends junit.framework.TestCase`) or BC `SimpleTest` classes
bridged with a JUnit `@Test` method.

The suite runs twice: always against JSL, and against the FIPS provider (`JSLFIPS`) when the
`TEST_FIPS_LIB` environment variable names an OpenSSL FIPS module. Tests therefore never name a
provider directly — they go through `JslTestProvider`, which installs whichever one is under test:

```java
JslTestProvider.install();                       // register the provider under test
... .setProvider(JslTestProvider.name());        // use it by name
```

Do **not** write `Security.addProvider(new JostleProvider())` or `JostleProvider.PROVIDER_NAME` in
a test. Both pin the run to the non-FIPS provider, and the failure is silent — the FIPS task
appears to pass while actually exercising JSL.

The FIPS module is a smaller surface than JSL, so a test needing something it lacks gates itself on
a probe of the provider rather than on a compliance judgement. See `.claude/guides/testing.md`.

## Versioning

- Library version: `version` in `gradle.properties` (tracks the bc-java
  release line it was rebuilt from, e.g. `1.86.0-SNAPSHOT`).
- Provider version: `jostleVersion` in `gradle.properties` (tracks the
  `openssl-jostle` artifact in `libs/`).

The two are independent — the libraries version with bc-java, the provider
versions with openssl-jostle.

## License

The bc-java-derived sources retain the [Bouncy Castle
license](https://www.bouncycastle.org/licence.html) (MIT-style).
