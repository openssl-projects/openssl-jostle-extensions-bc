---
name: jostle-mldsa-spki-encoding-gap
description: JSL provider emits non-matching ML-DSA SubjectPublicKeyInfo via KeyFactory vs X.509 cert path
metadata:
  type: project
---

JSL provider ML-DSA bug: `publicKey.getEncoded()` (KeyFactory path → `JOMLDSAPublicKey.getEncoded()` → `ASNEncoder.asSubjectPublicKeyInfo`) does NOT byte-equal `certificate.getPublicKey().getEncoded()` (X.509 cert path) for the same key. Breaks `getEncoded()`-equality (JSL keys use identity `equals()`).

**Symptom:** `bc-jostle-libs` pkix `NewSignedDataTest.testVerifySignedDataMLDsa{44,65,87}` fail with `IllegalStateException: public key mismatch` (thrown in `cert/test/SampleCredentials.load`). 81 run / 3 fail / 1 skip. RSA/DSA/EC/EdDSA all pass — ML-DSA only.

**Why it matters:** these are the long-standing pre-existing failures in the lib build; NOT caused by the core crypto cleanup (verified — reproduces on full un-pruned crypto; ML-DSA goes through the JSL native provider, not core software). Related to [[jostle-provider-aes-oid-gap]].

**How to apply:** issue filed at `bc-jostle-java/ISSUES/ml-dsa-spki-encoding-mismatch.md` (local doc; user to push to git.bouncycastle.org tracker). Fix is in bc-jostle-java JSL provider — diff the two SPKI encodings (suspect AlgorithmIdentifier params or BIT STRING/SPKI assembly mismatch between `ASNEncoder` and the cert path). When fixed, the 3 tests should pass and the build goes fully green.
