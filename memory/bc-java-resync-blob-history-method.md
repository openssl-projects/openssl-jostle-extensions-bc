---
name: bc-java-resync-blob-history-method
description: "How to scope a bc-java resync cheaply - classify each file by whether its exact bytes exist in upstream history, then only hand-merge the rest"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 2fff3d25-ec6a-4070-9c74-e8712717f323
  modified: 2026-08-16T12:58:34.505Z
---

When resyncing this fork with upstream bc-java, do **not** start by reading diffs. For each
differing file, ask whether its current bytes appear anywhere in upstream's history for that path
(`git log --format=%H -- <path>`, then `git cat-file --batch-check` the `<commit>:<path>` blobs and
compare against `git hash-object` of the local file).

- **Blob found** → the local file is unmodified upstream text from an older commit, so taking
  `main` verbatim is provably lossless. No reading required.
- **Blob not found** → the file carries a real local edit. Three-way merge it against its
  *closest* upstream ancestor (the historical blob with the smallest diff to local) and resolve
  conflicts by hand.

In the 1.85→1.86 resync this split 436 differing files into 376 mechanical and 60 needing thought,
and turned a multi-day read-everything job into a few hours. It also makes "no local adaptation was
silently reverted" a checkable claim rather than a promise.

**Do not use `git merge-file --ours` to bulk-resolve conflicts.** It resolves the conflicted hunks
in favour of local but still takes upstream's *non-conflicting* hunks, which in
`JceAsymmetricKeyWrapper`, `JcaPGPKeyPairGeneratorProvider` and `tls/PQCUtil` produced files that
mixed upstream imports with local bodies — one was not even syntactically valid. When a file's only
upstream drift is stuff this fork rejects anyway (GOST branches, software crypto, helper
indirection), just keep the local file whole and record it.

Related: [[jostle-libs-project]], [[dead-code-sweep-method]],
[[prefer-deleting-deprecated-over-rewriting]].
