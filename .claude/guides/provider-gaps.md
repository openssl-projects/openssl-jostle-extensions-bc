# JSL provider gaps

Status of capability gaps in the **JSL** (non-FIPS) provider, as consumed from
`libs/openssl-jostle-${jostleVersion}.jar`.

For **JSLFIPS**, see `testing.md`. Its restrictions are policy-driven and different in kind.

All statuses below were re-probed on 2026-08-19 against jar `0eaec46c`. Do not trust an older note;
re-probe before acting.

**Rule: provider gaps are fixed in `../openssl-jostle`, never here.** File a note in that repo's
`reviews/` directory with a probe, the expected behaviour, and how to verify. Do not edit that repo
or patch the jar.

## Open

| gap | symptom | impact |
|---|---|---|
| **No EAX cipher mode** | `Cipher.getInstance("AES/EAX/NoPadding")` → `NoSuchAlgorithmException: cipher mode EAX not supported`, from `BlockCipherSpi.engineSetMode` | RFC 9580 lists EAX as one of OpenPGP's three AEAD modes. v6 AEAD messages using it cannot be read or written. **OCB and GCM both work** — verified by full password-based round trips. |

## Closed

Kept because a stale "still broken" note is worse than none. Re-probed and confirmed working.

| former gap | resolution |
|---|---|
| AES not aliased to CMS content and wrap OIDs | Fixed. `Cipher.getInstance("2.16.840.1.101.3.4.1.46")` resolves. This had blocked CMS `EnvelopedData`. |
| No `AlgorithmParameters` for GCM | Fixed. `init(ENCRYPT, key)` with no params auto-generates a 12-byte IV and `getParameters()` returns it. |
| No native AES key wrap | Fixed. RFC 3394 and RFC 5649 both implemented. |
| Ed25519/Ed448 `KeyFactory` and `Signature` not registered under their curve OIDs | Fixed. `1.3.101.112` and `1.3.101.113` resolve. This had disabled 8 scenarios in `JcaTlsRawKeysProtocolTest`; the class is now 16/16. |
| ML-DSA SPKI encoding mismatch between the `KeyFactory` and X.509 cert paths | Fixed. `NewSignedDataTest` is 79/0; the three `testVerifySignedDataMLDsa*` tests pass. |
| No `SecretKeyFactory ARGON2` | Fixed. Present. OpenPGP v6 Argon2 S2K works through the `PGPS2KCalculator` seam. |
| `AESWrap` and its spellings resolved only by OID | Fixed. `AESWrap`, `AESWRAP`, `AESKW`, `AES/KW/NoPadding` and the padded variants all resolve, on both providers. |
| No `CertificateFactory` for X.509 | Fixed. Present. The old rule "never route cert conversion through JSL" no longer applies. |

## How to report a new one

The pattern that has worked, twice:

1. Probe it directly. Do not infer a provider defect from a test failure.
2. Write `../openssl-jostle/reviews/<topic>.md` with the probe output, the expected behaviour, a
   suggested fix and a verification step.
3. State whether it affects JSL, JSLFIPS or both. Several "FIPS gaps" turned out to affect both.
4. Include a cross-repo verification recipe: rebuild, stage the jar here, run both suites.

## Lessons from these

**Distinguish "the provider lacks it" from "our code asks wrongly".** Three TLS failures that looked
like provider gaps were `JcaTlsCrypto` advertising schemes the provider cannot perform. Suspect
over-reporting before filing.

**A capability claim needs a probe, not a reading.** Both repos produced confident, wrong claims from
reading code comments and policy tables. `testing.md` has the detail.

**`getInstance` succeeding is not proof.** For cipher modes the failure can appear at `init`.
