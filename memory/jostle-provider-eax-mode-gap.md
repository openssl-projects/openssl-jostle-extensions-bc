---
name: jostle-provider-eax-mode-gap
description: "JSL implements no EAX cipher mode, so OpenPGP v6 AEAD messages using EAX cannot be read or written"
metadata: 
  node_type: memory
  type: project
  originSessionId: 2fff3d25-ec6a-4070-9c74-e8712717f323
  modified: 2026-08-16T12:58:40.491Z
---

**Found 2026-08-16** during the bc-java 1.86 resync, by runtime probe against
`libs/openssl-jostle-0.1-SNAPSHOT.jar`.

`Cipher.getInstance("AES/EAX/NoPadding", "JSL")` fails with
`NoSuchAlgorithmException: cipher mode EAX not supported`, thrown from
`org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherSpi.engineSetMode`.

RFC 9580 lists EAX as one of OpenPGP's three AEAD modes, so any v6 AEAD message using it fails.
**OCB and GCM both work** — verified by full password-based encrypt/decrypt round trips through
`JcePBEKeyEncryptionMethodGenerator` / `JcePBEProtectionRemoverFactory`.

Provider-side, so it is fixed in `../openssl-jostle`, not here. Worth raising alongside
[[jostle-pg-argon2-provider-gap]]; the working pattern for cross-repo provider gaps is a note in
`../openssl-jostle/reviews/` (see how the ChaCha7539 key-algorithm regression was handled).

Related: [[jostle-libs-project]].
