#!/usr/bin/env python3
"""
Relocate every package from org.bouncycastle to org.bouncycastle.jsl.

  relocate.py count    - report the per-category counts, change nothing
  relocate.py apply    - move the directories and rewrite both forms
  relocate.py verify   - run the source post-checks (safe to run at any time)
  relocate.py jars     - step 7: assert no jar entry sits outside the jsl namespace
  relocate.py pending  - count the substitutions apply() would still make (0 once relocated)

The file set is what git tracks, so build outputs and the gitignored reviews/ tree are excluded by
construction. scripts/ is excluded explicitly: this file carries the old namespace in its own
pattern strings, and an apply that rewrote them would leave a script that no longer matches
anything. Docs (*.md) are skipped: they describe upstream bc-java as well as this
fork, so their hits are decided by hand.

RUNBOOK. After applying, run every gate from a CLEAN build - `./gradlew clean` first. Measured
2026-09-18: without it all three legs failed in :mail:compileTestJava with "package
org.bouncycastle.jsl.test does not exist", purely from stale incremental state describing the
pre-move layout, while the same task passed alone with --rerun-tasks. A rename of this size makes
both a green and a red result meaningless until the build state is discarded.

Two substitutions, both with a negative lookahead so the script is idempotent and so the four
places already on the target prefix are left alone:

    org\\.bouncycastle\\.(?!jsl\\b)  ->  org.bouncycastle.jsl.
    org/bouncycastle/(?!jsl/)       ->  org/bouncycastle/jsl/

Without the lookahead, the six module names, jslGroupId, core/build.gradle's module list and
build.gradle's startsWith('org.bouncycastle.jsl.') all become org.bouncycastle.jsl.jsl, and the
module-path legs then fail in a way that reads like a build bug.
"""

import os
import re
import subprocess
import sys

OLD_DOT = "org.bouncycastle"
NEW_DOT = "org.bouncycastle.jsl"
OLD_SLASH = "org/bouncycastle"
NEW_SLASH = "org/bouncycastle/jsl"

DOT_RE = re.compile(r"org\.bouncycastle\.(?!jsl\b)")
SLASH_RE = re.compile(r"org/bouncycastle/(?!jsl/)")

# Bare "org.bouncycastle" with nothing after it - the root package itself, exported by core.
BARE_DOT_RE = re.compile(r"org\.bouncycastle(?![.\w])")

DOCS = [
    "CLAUDE.md",
    "README.md",
    ".claude/guides/project.md",
    ".claude/guides/testing.md",
    ".claude/guides/conventions.md",
    ".claude/skills/port-from-bc-java/SKILL.md",
]


def repo_root():
    return subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=True).stdout.strip()


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
    # scripts/ is excluded from the file set: this script's own pattern strings spell the old
    # namespace, and an apply that rewrote them would leave a script matching nothing.
    return [f for f in out.split("\0") if f and not f.startswith("scripts/")]


def read(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(text)


def java(files):
    return [f for f in files if f.endswith(".java")]


def counts(files):
    c = {}

    pkg_files, packages, dirs = [], set(), set()
    import_lines = import_files = 0
    other = comment_other = link_other = 0
    for f in java(files):
        text = read(f)
        touched_import = False
        for line in text.splitlines():
            st = line.strip()
            if st.startswith("package org.bouncycastle"):
                pkg_files.append(f)
                packages.add(st[len("package "):].rstrip(";"))
                dirs.add(os.path.dirname(f))
            elif st.startswith("import ") and OLD_DOT in line:
                import_lines += 1
                touched_import = True
            elif OLD_DOT in line:
                other += 1
                if st.startswith("*") or st.startswith("//") or st.startswith("/*"):
                    comment_other += 1
                if "{@link" in line or "@see" in line:
                    link_other += 1
        if touched_import:
            import_files += 1

    c["1 source directories"] = len(dirs)
    c["2 package declarations (files)"] = len(pkg_files)
    c["2 package declarations (distinct)"] = len(packages)
    c["3 import lines"] = import_lines
    c["3 import files"] = import_files
    c["4 other in-code occurrences"] = other
    c["4 of those in comments"] = comment_other
    c["4 of those {@link}/@see"] = link_other

    exports = provides = 0
    module_infos = [f for f in files if f.endswith("src/main/java9/module-info.java")]
    for f in module_infos:
        for line in read(f).splitlines():
            st = line.strip()
            if st.startswith("exports org.bouncycastle"):
                exports += 1
            elif st.startswith("provides ") and OLD_DOT in st:
                provides += 1
    c["5 module-info exports"] = exports
    c["5 module-info provides"] = provides
    c["14 multi-release module-info files"] = len(module_infos)

    gradle_sites = 0
    for f in [x for x in files if x.endswith(".gradle")]:
        for line in read(f).splitlines():
            if OLD_DOT in line and not line.strip().startswith("//"):
                gradle_sites += 1
    c["6 gradle OSGi/module sites"] = gradle_sites

    services = [f for f in files if "/META-INF/services/" in f]
    c["7 META-INF/services files"] = sum(1 for f in services if OLD_DOT in read(f))

    i18n = 0
    for f in java(files):
        for line in read(f).splitlines():
            if "RESOURCE_NAME" in line and "=" in line and OLD_DOT in line:
                i18n += 1
    c["8 i18n bundle base names"] = i18n

    res = [f for f in files if "/src/" in f and "/resources/org/bouncycastle/" in f]
    c["9 resource files"] = len(res)
    c["9 resource directories"] = len({os.path.dirname(f) for f in res})

    slash = 0
    for f in java(files):
        slash += len(re.findall(r'"[^"\n]*org/bouncycastle[^"\n]*"', read(f)))
    c["10 slash-form literals"] = slash

    lits = {}
    for f in java(files):
        for m in re.findall(r'"org\.bouncycastle\.[A-Za-z0-9_.]*"', read(f)):
            lits[m] = lits.get(m, 0) + 1
    c["11 dotted literals (distinct)"] = len(lits)
    c["11 dotted literals (occurrences)"] = sum(lits.values())

    mailcap = [f for f in files if f.endswith("META-INF/mailcap")]
    c["12 mailcap lines"] = sum(
        sum(1 for line in read(f).splitlines() if OLD_DOT in line) for f in mailcap)

    props = [f for f in files if f.endswith("gradle.properties")]
    c["13 gradle.properties lines"] = sum(
        sum(1 for line in read(f).splitlines() if OLD_DOT in line) for f in props)

    tests = [f for f in java(files) if "/src/test/java/" in f or f.startswith("testsupport/")]
    c["15 test sources"] = len(tests)

    c["16 doc hits"] = sum(
        sum(1 for line in read(d).splitlines() if OLD_DOT in line)
        for d in DOCS if os.path.exists(d))

    return c


def pending(files):
    """What apply() would still change. Zero on an already-relocated tree.

    Counted with the same patterns and the same doc exclusion apply() uses, so this is the
    substitution's own fixed-point check rather than a restatement of it.
    """
    total = 0
    per_file = {}
    for f in tracked():
        if f in DOCS or f.endswith(".md"):
            continue
        if os.path.isdir(f):
            continue
        try:
            text = read(f)
        except (IsADirectoryError, FileNotFoundError):
            continue
        n = len(DOT_RE.findall(text)) + len(SLASH_RE.findall(text)) + len(BARE_DOT_RE.findall(text))
        if n:
            per_file[f] = n
            total += n
    return total, per_file


def move_dirs(files):
    """git mv every directory that holds a relocated package or resource, deepest first."""
    dirs = set()
    for f in java(files):
        for line in read(f).splitlines():
            if line.strip().startswith("package org.bouncycastle"):
                dirs.add(os.path.dirname(f))
                break
    for f in files:
        if "/src/" in f and "/resources/org/bouncycastle/" in f:
            dirs.add(os.path.dirname(f))

    # Move the shallowest org/bouncycastle root in each source set exactly once: moving
    # org/bouncycastle wholesale carries every package under it, so deep paths need no move.
    roots = set()
    for d in dirs:
        i = d.find("org/bouncycastle")
        roots.add(d[:i + len("org/bouncycastle")])

    # A source root may ALREADY hold an org/bouncycastle/jsl subtree - the test-support and jsl.test
    # packages do. Moving org/bouncycastle wholesale carries it along and buries it at
    # org/bouncycastle/jsl/jsl, while its package lines correctly stay put. Lift those back
    # afterwards; where the destination package already exists, merge file by file.

    moved = []
    for root in sorted(roots, key=lambda p: -p.count("/")):
        if not os.path.isdir(root):
            continue
        target = os.path.join(root, "jsl")
        tmp = root + ".d60tmp"
        subprocess.run(["git", "mv", root, tmp], check=True)
        os.makedirs(root, exist_ok=True)
        subprocess.run(["git", "mv", tmp, target], check=True)
        moved.append((root, target))

        buried = os.path.join(target, "jsl")
        if os.path.isdir(buried):
            for dirpath, _, filenames in os.walk(buried):
                for name in filenames:
                    src = os.path.join(dirpath, name)
                    dst = os.path.join(target, os.path.relpath(src, buried))
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    subprocess.run(["git", "mv", src, dst], check=True)
            for dirpath, dirnames, filenames in os.walk(buried, topdown=False):
                if not dirnames and not filenames:
                    os.rmdir(dirpath)
    return moved


def rewrite(files):
    """Rewrite every tracked file EXCEPT the docs.

    The guides and the porting skill describe upstream bc-java, whose packages stay
    org.bouncycastle.*, so a mechanical rewrite would make true sentences false. They are decided by
    hand in their own commit - see section 19.3 of the plan.
    """
    changed = 0
    for f in tracked():
        if f in DOCS or f.endswith(".md"):
            continue
        if os.path.isdir(f):
            continue
        try:
            text = read(f)
        except (IsADirectoryError, FileNotFoundError):
            continue
        if OLD_DOT not in text and OLD_SLASH not in text:
            continue
        out = DOT_RE.sub(NEW_DOT + ".", text)
        out = SLASH_RE.sub(NEW_SLASH + "/", out)
        out = BARE_DOT_RE.sub(NEW_DOT, out)
        if out != text:
            write(f, out)
            changed += 1
    return changed


SOURCE_ROOT_RE = re.compile(r"^(.*?/src/[^/]+/java[^/]*)/(.*)$")


def package_vs_directory():
    """Every .java under a source root must declare the package its directory spells.

    The first run of this script moved org/bouncycastle wholesale and carried the EXISTING
    org/bouncycastle/jsl subtree with it, so 27 files landed under org/bouncycastle/jsl/jsl while
    the dotted-form lookahead correctly left their package lines alone. Nothing caught it: javac and
    Gradle compile an explicit source list regardless of directory, so every gate stayed green. A
    content-only post-check cannot see this - it has to be checked against the PATH.
    """
    problems = []
    for f in tracked():
        if not f.endswith(".java") or f.endswith("module-info.java"):
            continue
        m = SOURCE_ROOT_RE.match(f)
        if not m:
            continue
        expected = os.path.dirname(m.group(2)).replace("/", ".")
        declared = None
        for line in read(f).splitlines():
            st = line.strip()
            if st.startswith("package "):
                declared = st[len("package "):].rstrip(";").strip()
                break
        if declared != expected:
            problems.append(f + ": declares " + str(declared) + ", directory says " + expected)
    return problems


def verify():
    problems = []
    for f in tracked():
        if "org/bouncycastle/jsl/jsl/" in f or "/jsl/jsl/" in f:
            problems.append(f + ": doubled jsl path segment")
    problems.extend(package_vs_directory())
    for f in tracked():
        if os.path.isdir(f):
            continue
        try:
            text = read(f)
        except (IsADirectoryError, FileNotFoundError):
            continue
        if "jsl.jsl" in text:
            problems.append(f + ": jsl.jsl")
        if "jsl/jsl" in text:
            problems.append(f + ": jsl/jsl")
        if "org.openssl.jostle.jsl" in text or "org/openssl/jostle/jsl" in text:
            problems.append(f + ": the provider namespace was rewritten")
        if '"BCJSSE"' not in text and False:
            pass
    for f in tracked():
        if "org/bouncycastle/" in f and "org/bouncycastle/jsl/" not in f:
            problems.append(f + ": path still outside the jsl namespace")
    return problems


def jar_check():
    """Step 7. A missed resource directory does not fail at compile time - it fails at runtime in a
    test that may be gated - so assert it at the artifact level."""
    import glob
    import zipfile

    problems = []
    jars = [j for j in glob.glob("*/build/libs/*.jar")
            if "sources" not in j and "javadoc" not in j]
    if not jars:
        return ["no artifacts built; run assemble first"]
    for j in jars:
        for name in zipfile.ZipFile(j).namelist():
            if not name.startswith("org/bouncycastle/"):
                continue
            if name.startswith("org/bouncycastle/jsl/"):
                continue
            # a bare parent directory entry carries nothing and is normal in a jar
            if name == "org/bouncycastle/":
                continue
            problems.append(os.path.basename(j) + ": " + name)
    print(f"checked {len(jars)} artifacts")
    return problems


def main():
    os.chdir(repo_root())
    mode = sys.argv[1] if len(sys.argv) > 1 else "count"
    files = tracked()

    if mode == "count":
        for k, v in counts(files).items():
            print(f"{v:>6}  {k}")
    elif mode == "apply":
        moved = move_dirs(files)
        print(f"moved {len(moved)} package roots")
        changed = rewrite(files)
        print(f"rewrote {changed} files")
        problems = verify()
        print("post-check: " + ("CLEAN" if not problems else f"{len(problems)} PROBLEMS"))
        for p in problems[:40]:
            print("  " + p)
        return 1 if problems else 0
    elif mode == "pending":
        total, per_file = pending(files)
        print(f"pending substitutions: {total}")
        for f, n in sorted(per_file.items())[:40]:
            print(f"  {n:>4}  {f}")
        return 0
    elif mode == "jars":
        problems = jar_check()
        print("step 7: " + ("CLEAN" if not problems else f"{len(problems)} PROBLEMS"))
        for p in problems[:40]:
            print("  " + p)
        return 1 if problems else 0
    elif mode == "verify":
        problems = verify()
        print("post-check: " + ("CLEAN" if not problems else f"{len(problems)} PROBLEMS"))
        for p in problems[:40]:
            print("  " + p)
        return 1 if problems else 0
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
