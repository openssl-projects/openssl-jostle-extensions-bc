---
name: dead-code-sweep-method
description: How to find/remove dead core classes reliably, and scope prunes to the package the user names
metadata:
  type: feedback
---

Two hard-won rules for the minimized-core dead-code prunes (the recurring "is X used / remove it / run the closure" tasks):

**1. Don't use a bare-token (`grep "\bClassName\b"`) closure to decide deadness — it both over- and under-counts.**
- Under-removes on name collisions: `crypto.modes.gcm.GCMUtil` looked "used" because `tls.crypto.impl.jcajce.GCMUtil` (a different class) shares the simple name. Same trap for `X25519`/`Ed25519` (the algorithm-name string + many same-named classes like `X25519PublicKeyParameters`, `JceX25519`).
- Determine deadness by RESOLVABLE references only: (a) `import org.bouncycastle.<pkg>.<Class>;` or inline FQN anywhere, OR (b) a same-package sibling using the bare name. If none of those → dead. Watch for wildcard imports (`import org.bouncycastle.bcpg.*;` exists, but bcpg is in the `pg` module, not core).

**2. NEVER run a reachability/closure analysis against a partially-deleted tree.** Deadness computed while files are missing is corrupted: a class whose only user is a not-yet-restored file looks dead and gets cascade-removed; restoring the user later breaks compilation. Incident (2026-06-13): a closure ran while `util/*` was deleted → cascade removed `SHAKEDigest`/`SHA512tDigest`; restoring `util/Fingerprint` (which uses them) then failed to compile. Always compute the dead set against the intact tree, remove in one shot, then compile+test.

**Scoping preference (user):** keep prunes tightly scoped to the exact package named. When a sweep surfaced 101 unreferenced classes across `asn1/jcajce/crypto/util/i18n/iana`, the user rejected the broad multi-package removal and said "remove only unused classes in the crypto package." Default to the narrowest scope the user states; surface the wider list but don't delete beyond it. Also prefer deleting unused/deprecated members over rewriting — see [[prefer-deleting-deprecated-over-rewriting]].

Verification is always: `./gradlew test --rerun-tasks` green (whole-repo baseline this era: 412 tests, 0 failures). See [[jostle-libs-core-recipe]], [[jostle-libs-core-closure]].
