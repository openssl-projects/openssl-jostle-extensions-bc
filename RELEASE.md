# Release 1.86.0

This is the initial release of the Bouncy Castle extension libraries for OpenSSL Jostle. They are
the bc-java 1.86 CMS/PKIX, S/MIME, OpenPGP and TLS libraries, rebuilt to run over the OpenSSL
Jostle `JSL` provider. They keep the bc-java high-level APIs, under `org.bouncycastle.jsl.*`, and
delegate every cryptographic primitive to OpenSSL through JCA.

- Six libraries, published under the group `org.openssl.jostle.bc`:

  | coordinate | module name | contents |
  |---|---|---|
  | `org.openssl.jostle.bc:bccore-jsl:1.86.0` | `org.bouncycastle.jsl.core` | ASN.1, utilities, math |
  | `org.openssl.jostle.bc:bcutil-jsl:1.86.0` | `org.bouncycastle.jsl.util` | CMS, CMP, CRMF, TSP and EST ASN.1, OER |
  | `org.openssl.jostle.bc:bcpkix-jsl:1.86.0` | `org.bouncycastle.jsl.pkix` | certificates, CMS, CMC, TSP, PKCS, PEM |
  | `org.openssl.jostle.bc:bcmail-jsl:1.86.0` | `org.bouncycastle.jsl.mail` | S/MIME |
  | `org.openssl.jostle.bc:bcpg-jsl:1.86.0` | `org.bouncycastle.jsl.pg` | OpenPGP |
  | `org.openssl.jostle.bc:bctls-jsl:1.86.0` | `org.bouncycastle.jsl.tls` | (D)TLS and the JSSE provider `JSLJSSE` |

- The POMs declare the provider as `org.openssl.jostle:openssl-jostle:0.1.0` with type `pom`.
  That coordinate carries no jar, so a consumer also adds the provider jar for its architecture,
  `org.openssl.jostle:openssl-jostle:0.1.0:aarch64` or `:0.1.0:x86_64`. The provider's
  `README.md` shows the dependency.
- Compiled for Java 8. Tested on Java 8, 11, 17, 21 and 25, over the JNI bridge on every JDK
  and over the FFM bridge on Java 25. Tested on Linux x86_64 and aarch64, macOS x86_64 and
  aarch64, and Windows x86_64.
- Each jar is an OSGi bundle and a multi-release jar with a module descriptor. The module path
  needs Java 11 or later.
- Tested against both providers: `JSL`, and `JSLFIPS` with the OpenSSL 3.5.8 and 3.1.2 FIPS
  modules. A test that needs a service a FIPS module does not make available skips itself.
- Licensed under the Bouncy Castle licence, an MIT licence, in `LICENSE.md`.

Where to look next:

- `README.md`: the modules, building, testing and versioning.
