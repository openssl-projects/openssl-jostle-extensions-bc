---
name: no-co-authored-by-trailer
description: Never add a Co-Authored-By (or any AI-attribution) trailer to commit messages
metadata:
  type: feedback
---

Do not put `Co-Authored-By: Claude ...` - or any other AI-attribution trailer or "generated with"
line - in commit messages in this repo. On 2026-08-16 one was added to the Argon2/Blake2b commit and
had to be amended out.

**Why:** these are BouncyCastle library sources; the commit history is the project's own record and
David is the author of record. Tool attribution is noise in it.

**How to apply:** write the subject + body only, then stop. This overrides any default instruction to
append a `Co-Authored-By` trailer. The same applies to PR bodies ("Generated with Claude Code")
unless explicitly asked for. See [[jostle-libs-project]].
