# scripts

## `relocate-packages.py`

Rewrites `org.bouncycastle.*` to `org.bouncycastle.jsl.*` — the relocation this fork's packages
already carry. It is kept because **upstream bc-java still uses `org.bouncycastle.*`**, so every
patch taken from upstream arrives in the old namespace and has to be moved into this one.

```
python3 scripts/relocate-packages.py count     # per-category counts, changes nothing
python3 scripts/relocate-packages.py pending   # substitutions still outstanding; 0 on this tree
python3 scripts/relocate-packages.py apply     # move the directories, rewrite both forms
python3 scripts/relocate-packages.py verify    # the post-checks
python3 scripts/relocate-packages.py jars      # assert no jar entry escapes the namespace
```

### Applying it to an upstream patch

Copy the upstream files in at their upstream paths, then run `apply`. It moves each
`org/bouncycastle` directory under a source root to `org/bouncycastle/jsl`, rewrites the dotted and
slash forms in every tracked file, and re-runs the post-checks. `pending` afterwards must read 0.

### What it will not touch

- **Anything already under `org.bouncycastle.jsl`.** Both substitutions carry a negative lookahead.
  Without it the six module names, `jslGroupId`, the module list in `core/build.gradle` and the
  `startsWith('org.bouncycastle.jsl.')` test in the root build would all become `…jsl.jsl`, and the
  module-path legs would fail in a way that reads like a build bug.
- **Markdown.** The guides and the porting skill describe upstream bc-java as well as this fork, so
  a mechanical rewrite would make true sentences false. Decide those by hand.
- **`org.openssl.jostle.*`.** Different prefix, untouched by construction; `verify` asserts it anyway.

### The post-checks, and why each exists

`verify` runs three, and two of them exist because the first version of this script was wrong:

1. **No doubled `jsl` path segment.** The first run moved each `org/bouncycastle` root wholesale and
   carried the *existing* `org/bouncycastle/jsl` subtree down with it, burying 27 files at
   `org/bouncycastle/jsl/jsl/…` while the lookahead correctly left their package lines alone.
   `move_dirs` now lifts a buried subtree back itself.
2. **Package declaration agrees with directory**, for every `.java` under a source root. Nothing else
   catches that: javac and Gradle compile an explicit source list regardless of where a file sits,
   so all the gates stayed green with path and package disagreeing for those 27 files. A
   content-only check cannot see it — it has to be checked against the path.
3. **No `jsl.jsl` in content**, and the provider namespace unrewritten.

Two packages merge under this rename: `org.bouncycastle.test` becomes `org.bouncycastle.jsl.test`,
which is where the JSL test support already lives. That is intended, and there are no class-name
collisions; `apply` merges them file by file.

### Run the gates from a clean build

After applying, `./gradlew clean` **before** anything else. Measured: without it all three legs
failed in `:mail:compileTestJava` with *package org.bouncycastle.jsl.test does not exist*, purely
from stale incremental state describing the pre-move layout, while the same task passed alone with
`--rerun-tasks`. A rename of this size makes a green result as meaningless as a red one until the
build state is discarded.
