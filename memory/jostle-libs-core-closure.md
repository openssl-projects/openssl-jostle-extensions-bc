---
name: jostle-libs-core-closure
description: How the minimal core module for bc-jostle-libs is sized — jdeps closure findings
metadata:
  type: reference
---

For [[jostle-libs-project]], the `core` module size was analysed with jdeps.

Method: exploded all bc-java module class trees + jostle jar into a flat pool (module-info stripped, else jdeps fails module resolution: "Module org.bouncycastle.provider not found"). Ran `$BC_JDK21/bin/jdeps -verbose:class -recursive -cp pool roots` where roots = util/pkix/mail/pg/tls main classes. Artifacts were kept under `bc-jostle-libs/build-analysis/`, but that 67MB scratch dir (jdeps closure, class lists, exploded pool/roots, prune manifest) has since been DELETED — it was not consumed by the build/scripts and was a one-time pre-prune upstream snapshot. Regenerate by re-running the jdeps step above if needed.

Result: satellite libs transitively reference **4481** distinct `org.bouncycastle` classes; **1955** of them live in bcprov (core+prov). NOTE: bc-java `prov` build output already contains all of `core` (coreprov union == prov == 5512).

**The raw closure is NOT minimal.** It is dominated by BC software crypto that jostle is meant to replace: pqc.crypto(302), pqc.jcajce(293), math.ec(228), crypto.params(77)/signers(46)/digests(33)/engines(26)/generators(23)/modes(22). These get pulled in transitively through `org.bouncycastle.jce.provider.BouncyCastleProvider` — and `jcajce.util.BCJcaJceHelper` imports BouncyCastleProvider, so any use of the jcajce helpers drags the whole engine set in.

Therefore minimal core ≈ asn1.** + util.** + math.** + internal.** + i18n/iana + non-engine crypto types (params/interfaces) + jcajce support (spec/io/interfaces/util). EXCLUDE crypto engines/modes/signers/generators, pqc.**, and jce/provider engine SPIs. Handle BouncyCastleProvider via a thin shim OR exclude BCJcaJceHelper and route through NamedJcaJceHelper/ProviderJcaJceHelper with provider "JSL". Each excluded class that satellite source references directly becomes a documented source delta vs bc-java (the bc-fips-libs `list.txt` model) — i.e. that code path uses BC software crypto and must be patched/removed.
