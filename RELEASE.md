# Release 1.87.0

- Rebuilt from bc-java 1.87 (tag `r1rv87`). This brings in the RFC 9980 post-quantum OpenPGP
  keys, built on the provider's ML-DSA, SLH-DSA and ML-KEM, and the C509 certificate and request
  builder, holder, converter and content verifier provider builder classes.
- Requires, and is built and tested against, the OpenSSL Jostle provider 0.3.0. The POMs declare
  `org.openssl.jostle:openssl-jostle:0.3.0` with type `pom`, so a consumer adds
  `org.openssl.jostle:openssl-jostle:0.3.0:aarch64` or `:0.3.0:x86_64`. The provider's own changes
  are listed in the OpenSSL Jostle 0.3.0 release notes.
- Tested against `JSL`, and `JSLFIPS` with the OpenSSL 3.5.9 and 3.1.2 FIPS modules.
- The TLS ML-KEM and hybrid groups use the ML-KEM shared secret as TLS specifies, with no key
  derivation applied to it.
- A 1.87.0 peer and a 1.86.x peer of these libraries do not complete a handshake on an ML-KEM or
  hybrid group: move both ends together, or have them negotiate another group.
- Brings in DTLS 1.3 from bc-java 1.87. Its ChaCha20 record number mask is computed with the
  provider's `ChaCha20` cipher and counter spec, so `TLS_CHACHA20_POLY1305_SHA256` is available over
  DTLS 1.3 on `JSL`.
- An ML-KEM key from another provider is passed to the provider, which takes it by its encoding.
- CMS key agreement offers the cofactor ECDH schemes on `JSL` and `JSLFIPS`, and CMS offers the
  Triple-DES key wrap (`id-alg-CMS3DESwrap`) on `JSL` only; both come from jostle 0.3.0. The wrap
  takes a 24-byte key-encryption key only.

# Release 1.86.1

- Built and tested against the OpenSSL Jostle provider 0.2.0. The POMs declare
  `org.openssl.jostle:openssl-jostle:0.2.0` with type `pom`, so a consumer adds
  `org.openssl.jostle:openssl-jostle:0.2.0:aarch64` or `:0.2.0:x86_64`.
- Tested against `JSL`, and `JSLFIPS` with the OpenSSL 3.5.9 and 3.1.2 FIPS modules. The 3.5.8
  module is no longer tested.
- OpenPGP armor and the EST client read and write UTF-8, whatever the platform charset.

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
