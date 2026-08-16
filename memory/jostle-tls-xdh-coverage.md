---
name: jostle-tls-xdh-coverage
description: X25519/X448 TLS test coverage added, plus the JSL-provider TLS integration gaps discovered while adding it
metadata:
  type: project
---

X25519/X448 TLS coverage for bc-jostle-libs (added 2026-06-08, full suite 306 green). Related: [[jostle-pkix-test-migration]], [[jostle-libs-core-recipe]].

**What was added:** `tls/src/test/.../TlsProtocolXDHTest.java` (abstract) + `JcaTlsProtocolXDHTest.java` (concrete, uses `TlsTestUtils.createTestCrypto()`). `testX25519`/`testX448` run an in-memory TLS 1.3 handshake forcing supportedGroups + earlyKeyShareGroups to the single group, assert echo round-trip and negotiated group. Driven over an **external-PSK `psk_dhe_ke`** exchange (reuses `MockPSKTls13Client`/`Server`) deliberately — PSK auth needs NO server certificate signature, so it isolates the X25519/X448 (EC)DHE key agreement from the unrelated server-auth gaps below.

**Verified working in JSL-backed `JcaTlsCrypto`:** `hasNamedGroup(x25519)`=`hasNamedGroup(x448)`=true; full TLS 1.3 ECDHE handshake completes and negotiates x25519(29) / x448(30). JSL KeyAgreement X25519=32 bytes, X448=56 bytes.

**One in-repo fix this required** — `tls/.../crypto/impl/jcajce/JcaTlsHash.java`: JSL's `MessageDigest` is NOT cloneable (native state; `getInstance("SHA-256","JSL").clone()` throws `CloneNotSupportedException`), but the TLS transcript hash must be cloned → handshake died with `UnsupportedOperationException`. Fixed JcaTlsHash to probe cloneability once at construction; if not cloneable, buffer fed bytes and rebuild a cloneable platform digest (`MessageDigest.getInstance(algorithm)`, JDK SUN) on `cloneHash()`. `calculateHash`/`reset` keep the buffer consistent. Benefits all JSL-backed TLS, not just this test.

**ML-KEM-in-TLS — FIXED 2026-06-08 (in-repo, was NOT a provider bug).** Pure `MLKEM512/768/1024`
and the `X25519MLKEM768` hybrid now complete TLS 1.3 handshakes (tests: `TlsProtocolHybridKemTest`
/ `JcaTlsProtocolHybridKemTest`, PSK `psk_dhe_ke`, group-forcing + data echo). Root cause: the
satellite's TLS `KemUtil`/`JceTlsMLKemDomain`/`JceTlsMLKem` were hardcoded to BC's
`org.bouncycastle.jcajce.*` KEM API (`MLKEMParameterSpec`/`KEMGenerateSpec`/`KEMExtractSpec`/
`SecretKeyWithEncapsulation`/`MLKEMPublicKey`), but JSL exposes the parallel
`org.openssl.jostle.jcajce.*` types — so `KPG("ML-KEM").initialize(bcSpec)` threw
`InvalidAlgorithmParameterException: only MLKEMParameterSpec is supported got
org.bouncycastle.jcajce.spec.MLKEMParameterSpec` (same simple name, different package),
`isKemSupported` returned false → `hasNamedGroup(MLKEM768)=false` → hybrid never offered →
server `handshake_failure(40)`. Fix: ported those 3 files to JSL's KEM types. JSL KEM
`KeyGenerator` with `keySizeInBits=256` returns the raw 32-byte ML-KEM shared secret (no KDF).
Gotcha: JSL `MLKEMParameterSpec.fromName` is case-sensitive lower-case (`"ml-kem-768"`), so
`KemUtil` lower-cases `NamedGroup.getKemName()`. NOTE: `hasNamedGroup(hybrid)` itself still
returns false by design (no hybrid branch in `isSupportedNamedGroup`); TLS decomposes hybrids via
`NamedGroup.getHybridFirst/Second` and checks each component — so test support guards must do the
same (see `TlsProtocolHybridKemTest.supportsGroup`).

**NIST-curve TLS groups — FIXED 2026-06-08 (in-repo consumer-side shim, no provider mixing).** Pure NIST ECDHE (`secp256r1/384/521`) and the `SecP256r1MLKEM768`/`SecP384r1MLKEM1024` hybrids now complete TLS 1.3 handshakes (added to `TlsProtocolHybridKemTest`). Three findings + the shim (in TLS `ECUtil`/`JceTlsECDomain`): (1) JSL registers NO `AlgorithmParameters "EC"`, BUT that's not fatal — `ECUtil.getECParameterSpec` falls back to generating a throwaway keypair and reading `((ECKey)priv).getParams()`, and JSL EC keys DO implement `java.security.interfaces.ECKey`/`ECPublicKey` with a full `getParams()`. (2) JSL EC KPG rejects `secp256r1` ("not supported by the loaded OpenSSL build") but accepts `prime256v1`/`P-256` — OpenSSL only registers P-256 under the X9.62 name; secp384r1/secp521r1 are fine. Added `ECUtil.jslCurveName()` mapping `secp256r1`→`prime256v1`. (3) JSL EC KPG rejects an explicit-parameter `ECParameterSpec` (wants a named curve), so `JceTlsECDomain.generateKeyPair` now inits with `ECGenParameterSpec(jslCurveName)` not `ecSpec`; JSL `KeyFactory("EC")` DOES accept explicit `ECPublicKeySpec` so peer-key decode was already fine. All keys stay JSL-native (no SunEC mixing). Optional provider niceties (would let the shim be dropped) in `openssl-jostle/docs/JCA_TLS_GAPS.md` #2.

**JSL TLS server-cert-auth gaps still open (need provider fixes; recorded in `openssl-jostle/docs/JCA_TLS_GAPS.md`):**
- **Server RSA auth: no `NoneWithRSA`** — JSL doesn't register raw RSA Signature, so TLS 1.3 server CertificateVerify with RSA creds throws `NoSuchAlgorithmException: NoneWithRSA`. (JSL has RSASSA-PSS, SHAxxxWITHRSA(ANDMGF1), ECDSA, ED25519/448, ML-DSA, SLH-DSA.)
- **Server Ed25519 auth: key-type mismatch** — client verify routes to SunEC Ed25519 engine which rejects the JSL-decoded key (`InvalidKeyException: expected only EdDSAPublicKey`). Provider/key-class mixing in the Tls13Verifier path.

Net: fully covered — X25519/X448 ECDHE (`TlsProtocolXDHTest`); pure ML-KEM, pure NIST ECDHE
(secp256r1/384/521), and ALL THREE ML-KEM hybrids X25519MLKEM768/SecP256r1MLKEM768/SecP384r1MLKEM1024
(`TlsProtocolHybridKemTest`, 9 methods). Only certificate-authenticated handshakes remain limited
(RSA/Ed25519 server-auth gaps). Full suite 315 green (tls=27).
