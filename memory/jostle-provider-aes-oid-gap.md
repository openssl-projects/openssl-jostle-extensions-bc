---
name: jostle-provider-aes-oid-gap
description: AES OID aliases FIXED in JSL provider; CMS EnvelopedData still blocked by two deeper GCM/AES-KW gaps
metadata:
  type: project
---

**UPDATE 2026-06-05: the AES OID alias gap is FIXED.** Edited `../openssl-jostle` `jostle/.../jcajce/provider/ProvAES.java`: the sized AES KeyGenerators are now aliased to their ECB/CBC/GCM NIST OIDs, and Cipher implementations are registered for the GCM OIDs (id_aes128/192/256_GCM) alongside the existing CBC ones; also fixed a latent bug where the AES128-CBC OID cipher was built with `OSSLMode.ECB`. Rebuilt the jar with `JAVA_HOME=/opt/jdk-25 ./gradlew :jostle:jar -x test` (the java25 FFI source set needs a Java 25 compiler; gradle otherwise runs on 17) and re-staged it into `bc-jostle-libs/libs/`. Verified: `KeyGenerator`/`Cipher.getInstance("2.16.840.1.101.3.4.1.46","JSL")` now resolve. The openssl-jostle source change is uncommitted in that repo.

**Gap 1 (GCM AlgorithmParameters) — FIXED 2026-06-05.** Edited `BlockCipherSpi` (both `java/` and `java9/` source sets — the java9 copy uses the `try{}finally{Reference.reachabilityFence(this)}` idiom, not `synchronized`): added `ivBytes`/`tagLen` fields; `engineInit(opmode,key,random)` now delegates to the spec form which, for ENCRYPT/WRAP with null params, auto-generates a random IV (12 bytes for GCM/OCB via new `autoIvLength()`, block size otherwise); `engineGetIV()` returns the IV; `engineGetParameters()` returns `AlgorithmParameters.getInstance("GCM"|keyAlgorithm)` initialised with the IV/tag. Also removed `AESBlockCipherSpi`'s `engineInit(...,AlgorithmParameters,...)` override which only extracted `IvParameterSpec` (broke GCM-decrypt-from-params); the base already tries both specs. Verified: GCM cipher by OID, `init(ENCRYPT,key)` with no params → 12-byte auto IV → `getParameters()` returns GCM params → decrypt round-trips; and `JceCMSContentEncryptorBuilder(AES256_GCM).setProvider("JSL").build()` now succeeds. Locked in by `AesGcmTest.gcmAutoGeneratesIvAndExposesParameters` in the libs suite (now 8 tests, 7 pass, 1 skip).

**Gap "native AES key-wrap" — FIXED 2026-06-05 (AES-KW RFC 3394 + AES-KWP RFC 5649).** Implemented in `../openssl-jostle`:
- Native `interface/util/block_cipher_ctx.c`: added WRAP/WRAP_PAD cases for AES128/192/256 (`EVP_CIPHER_fetch("AES-NNN-WRAP[-PAD]")`); treat as no-IV (default ICV); set `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` before EVP init (OpenSSL gates wrap behind it); bypass the 16-byte block-alignment check and the out_len<in_len guard for wrap (KW needs mult-of-8 ≥16, KWP arbitrary); wrap-aware output sizing in `final_size` and `block_cipher_get_update_size` (encrypt KW len+8 / KWP roundup8+8; decrypt len-8 upper bound).
- Java `BlockCipherSpi` (java/ + java9/): map `WRAP_MODE→ENCRYPT_MODE`, `UNWRAP_MODE→DECRYPT_MODE` for native (native only knows encrypt/decrypt); added `engineWrap`/`engineUnwrap` (CipherSpi defaults throw) that route through `engineDoFinal` and rebuild the key (SecretKeySpec / X509/PKCS8 via KeyFactory).
- `ProvAES`: registered Cipher + KeyGenerator OID aliases for `id_aes{128,192,256}_wrap` and `_wrap_pad`.
- Build: native via `PATH=/opt/cmake-3.31.6-linux-x86_64/bin:$PATH OPENSSL_PREFIX=../openssl_3_6 JAVA_HOME=/opt/jdk-25 interface/build.sh` (system cmake 3.28 is too old; project needs ≥3.30), then `:jostle:jar`. Verified: `AESKeyWrapTest` (RFC 3394 vector + BC interop KW/KWP + tamper + non-aligned rejection) 36/0, no suite regressions; `aes256-wrap` now resolves by OID. Re-staged jar into `bc-jostle-libs/libs/`.

**ONE gap remains before the ML-KEM CMS envelope works** (`MLKEMEnvelopedDataTest` stays @Ignore): ML-KEM not registered as a Cipher/KEM by OID (2.16.840.1.101.3.4.4.2) for the encapsulation step — see [[jostle-mlkem-cms-kts-design]]. AES key-wrap (the other half) is now done.

----
Originally found while building the runtime test harness for [[jostle-libs-project]] (2026-06-05):

The OpenSSL Jostle (JSL) provider registers AES only under the name `"AES"`. It does NOT register the AES KeyGenerator or Cipher under the per-mode NIST OIDs that CMS resolves algorithms by — e.g. `2.16.840.1.101.3.4.1.46` (aes256-GCM) and `2.16.840.1.101.3.4.1.45` (aes256-wrap). Probed directly: `KeyGenerator.getInstance("AES","JSL")` and `Cipher.getInstance("AES","JSL")` work; the same by OID throw `NoSuchAlgorithmException`.

Impact: CMS `EnvelopedData` cannot run fully through JSL. `JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider("JSL").build()` fails in `EnvelopedDataHelper.createKeyGenerator`, and the ML-KEM recipient's AES key-wrap fails the same way. Because a recipient generator takes a SINGLE provider (ML-KEM must be JSL; AES-wrap then also routes to JSL), there is no clean provider split.

This is a **jostle provider fix**, not a compat-lib issue: `JostleProvider` should add OID aliases for its AES (and other symmetric) KeyGenerator/Cipher entries — at minimum aes128/192/256 GCM/CBC and the aes*-wrap / wrap-pad OIDs. The test `MLKEMEnvelopedDataTest` in pkix is `@Ignore`d with this reason and should be re-enabled once the aliases land. ML-DSA/SLH-DSA cert + CMS SignedData paths already pass (they use JDK for the SHA digest and JSL only for the signature).
