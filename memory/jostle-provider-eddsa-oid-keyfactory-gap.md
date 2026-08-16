---
name: jostle-provider-eddsa-oid-keyfactory-gap
description: RESOLVED — JSL now aliases KeyFactory+Signature to the Ed25519/Ed448 OIDs; all TLS RFC 7250 raw-key tests re-enabled
metadata:
  type: project
---

**RESOLVED 2026-06-13.** Fixed in `../openssl-jostle` `ProvED.configureEDDSA`: added OID aliases for both `KeyFactory` and `Signature` — `addAlias("KeyFactory","ED25519",EdECObjectIdentifiers.id_Ed25519)` (1.3.101.112) + `ED448` (.113), and the same for `Signature` (mirrors `ProvMLDSA`). Rebuilt `:jostle:jar`; the fresh jar was re-staged into `libs/openssl-jostle-1.0-SNAPSHOT.jar` (the build alone does NOT copy it — the old jar had to be overwritten). Probe now: `KeyFactory`/`Signature.getInstance("1.3.101.112","JSL")` resolve. The 8 `DISABLED_` scenarios in `JcaTlsRawKeysProtocolTest` were re-enabled (drop `DISABLED_` prefix) → class now 16/16, tls suite 50→58, whole repo 412 passing. Full gap write-up: `../openssl-jostle/docs/RAW_EDWARDS_OID_GAP.md` (status RESOLVED). Original report below.

**Gap (found 2026-06-13).** The JSL provider registers a `KeyFactory` for Ed25519 only under the *names* `"Ed25519"` and `"EdDSA"`, NOT under the curve OID `1.3.101.112` (and, by extension, Ed448 `1.3.101.113`). Probed directly against `libs/openssl-jostle-1.0-SNAPSHOT.jar`:

```
KeyFactory.getInstance("Ed25519","JSL")     -> OK
KeyFactory.getInstance("EdDSA","JSL")        -> OK
KeyFactory.getInstance("1.3.101.112","JSL")  -> NoSuchAlgorithmException
```

**Where it bites.** `tls/.../jcajce/JcaTlsRawKeyCertificate.getPublicKey()` (verbatim bc-java main source) rebuilds the peer's public key with
`crypto.getHelper().createKeyFactory(keyInfo.getAlgorithm().getAlgorithm().getId())` — i.e. KeyFactory **by OID string**. For an Ed25519 raw public key that id is `1.3.101.112`, so the lookup throws and `getPublicKey()` wraps it as `TlsFatalAlert(unsupported_certificate)`. The handshake aborts in `verifyServerKeyExchangeSignature` → `TlsECDHEKeyExchange.processServerKeyExchange`.

Note the asymmetry: raw-key credential *generation* works (it uses `createKeyPairGenerator("Ed25519")` + `jcaCrypto.createCertificate(...)`, both by name). Only peer-key *verification* (KeyFactory-by-OID) fails. Same root cause shape as [[jostle-provider-aes-oid-gap]] and [[jostle-mldsa-spki-encoding-gap]] — JSL registers by name but not by the OID alias that the generic JCA-helper paths resolve through.

**Impact on tests.** `pkix`/`tls` RFC 7250 raw-public-key support was synced from bc-java (main: `JcaTlsRawKeyCertificate` added, `JcaTlsCrypto.createCertificate` switch wired for `CertificateType.RawPublicKey`). The migrated `JcaTlsRawKeysProtocolTest` (extends the now-`abstract` `TlsRawKeysProtocolTest`; mocks `MockRawKeysTls{Client,Server}` copied; `TlsTestUtils.createRawKeyEd25519Credentials` added as a Jca-only helper) runs **16 scenarios: 8 pass, 8 disabled**. The 8 passing are extension-negotiation only (no raw-key verify). The 8 `DISABLED_` ones all complete a handshake that verifies a peer Ed25519 raw key — they hit this gap. They are renamed `testXxx`→`DISABLED_testXxx` in the base class (JUnit3 skip convention from [[jostle-pkix-test-migration]]).

**Fix (belongs in `../openssl-jostle`, not the compat libs).** In the EdDSA provider registration (`Prov*`/`JostleProvider`), add `provider.addAlias("KeyFactory", "Ed25519", new ASN1ObjectIdentifier("1.3.101.112"))` and the Ed448 equivalent (`1.3.101.113`) — the `ASN1ObjectIdentifier` overload registers both bare and `OID.`-prefixed forms (repo convention). A full rebuild needs JDK 25 (the `java25` FFI source set); per CLAUDE.md, the stopgap is to recompile the changed class with JDK 17 `--release 9` and hot-patch both the base and `META-INF/versions/9/...` entries into the jar. Once the alias lands, re-enable the 8 `DISABLED_` raw-key handshake tests (drop the `DISABLED_` prefix) and they should pass — JSL signs/verifies Ed25519 fine; only the OID-keyed KeyFactory lookup is missing.
