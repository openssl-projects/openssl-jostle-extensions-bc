---
name: prefer-deleting-deprecated-over-rewriting
description: When a software-crypto dep lives only in a deprecated member, delete the member rather than rewriting it to JCA
metadata:
  type: feedback
---

When removing a minimized-core software-crypto dependency (e.g. `crypto.digests.SHA1Digest`/`SHA256Digest`) from a class, and the only remaining usage is inside a **`@deprecated`** method/constructor, **delete the deprecated member** instead of rewriting it to `MessageDigest.getInstance(...)`.

Concrete case (2026-06-13): `core/.../asn1/x509/AuthorityKeyIdentifier` had two `@deprecated` SPKI constructors that computed the key id via `new SHA1Digest()`. I started rewriting them to `MessageDigest`; the user said "delete the deprecated constructors instead." They were unused repo-wide (callers use `X509ExtensionUtils` → the `byte[]` constructors), so deletion removed the `SHA1Digest` dep cleanly.

**Why:** rewriting keeps dead/deprecated API alive and drags a JCA-provider dependency + exception handling into a fundamental core ASN.1 class; deleting shrinks the surface and is the intended direction for this minimized core. Test helpers and live code still get the `MessageDigest.getInstance("SHA1"/"SHA256")` rewrite — only deprecated members are deleted.

**How to apply:** before rewriting a class to drop a software-crypto dep, check whether the usage sits in a `@deprecated` member and whether that member is called anywhere in the repo (`grep -rn "new ClassName("`). If deprecated AND unused → delete it (and any sibling that only delegates to it), then prune the now-unused imports. Only rewrite to JCA when the member is live/non-deprecated. See [[jostle-libs-core-recipe]].
