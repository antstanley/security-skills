#!/usr/bin/env python3
"""Generate the installable, self-contained skills/ tree from src/.

src/ is the canonical source. Each skill under src/skills/<name>/ is copied to
skills/<name>/ together with the shared references, scripts, and schemas it
needs, so every skill folder works on its own. That matters because installers
(the Vercel `skills` CLI, install.sh, a manual copy) move a single skill
directory and nothing else.

Shared files are included when a skill's text (or the text of another included
shared file) mentions their file name. A Python helper is included when Markdown
or JSON text names its `.py` file, or when an included helper actually loads it
(an import, a `_load_script("name")` call, or a literal "name.py" path). Links
written as `../../references/x.md` are rewritten to `references/x.md` so they
resolve inside the copied folder.

Never edit skills/ by hand. Edit src/, then run this script.

Usage:
    scripts/sync-skills.py           regenerate ./skills from ./src
    scripts/sync-skills.py --check   exit 1 if ./skills is out of date
"""

import argparse
import filecmp
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUT = ROOT / "skills"

SHARED = ("references", "scripts", "schemas")
SKIP_DIRS = {"evals", "__pycache__", ".ruff_cache", ".pytest_cache"}
SKIP_FILES = {".DS_Store"}
TEXT_SUFFIXES = {".md", ".py", ".json", ".toml"}

# `../../references/x.md` (any depth of `../`) -> `references/x.md`, and
# `../sibling-skill/references/x.md` -> `references/x.md`. Both forms are
# resolved against a copy of the file that sits inside the skill itself.
UP_LINK = re.compile(r"(?:\.\./)+(?:[\w.-]+/)?(references|scripts|schemas)/")


def iter_files(root: Path):
    """Yield files under root, skipping caches and evaluation artifacts."""
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in SKIP_FILES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def skill_dirs():
    for skill_md in sorted((SRC / "skills").glob("*/SKILL.md")):
        yield skill_md.parent


def shared_index():
    """Map each shared file's name to its source path, rejecting collisions.

    Covers the top-level shared resources and every skill's own references/,
    because a skill may link to a sibling skill's reference document.
    """
    sources = [SRC / resource for resource in SHARED]
    sources += [skill / "references" for skill in skill_dirs()]
    index: dict[str, Path] = {}
    for source in sources:
        for path in iter_files(source):
            if path.name in index:
                sys.exit(f"sync-skills: file name collision: {path.name}")
            index[path.name] = path
    return index


def text_of(path: Path) -> str:
    if path.suffix not in TEXT_SUFFIXES:
        return ""
    return path.read_text(encoding="utf-8")


# How one helper loads another: `import x` / `from x import ...`,
# `_load_script("x")`, or a literal file name such as `with_name("x.py")`.
SCRIPT_DEPENDENCY = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+(\w+)"
    r"|_load_script\(\s*[\"'](\w+)[\"']\s*\)"
    r"|[\"'](\w+)\.py[\"']",
    re.MULTILINE,
)


def script_loads(text: str) -> set[str]:
    """Return the `<module>.py` file names a Python source actually loads."""
    return {
        f"{next(group for group in match.groups() if group)}.py"
        for match in SCRIPT_DEPENDENCY.finditer(text)
    }


def mentions(text: str, name: str, *, python_source: bool) -> bool:
    """Whether text refers to a shared file.

    Prose must name a helper by its full file name (`preflight.py`): a bare stem
    is too often an ordinary word ("run the preflight"). Inside a Python helper,
    only real loads count, so a comment that mentions a sibling does not pull it in.
    """
    if name.endswith(".py"):
        if python_source:
            return name in script_loads(text)
        return re.search(rf"(?<![\w-]){re.escape(name)}(?!\w)", text) is not None
    return name in text


def shared_closure(skill: Path, index: dict[str, Path]) -> set[str]:
    """Return the shared file names a skill needs, following mentions transitively."""
    needed: set[str] = set()
    pending = [(text_of(p), p.suffix == ".py") for p in iter_files(skill)]
    while pending:
        text, python_source = pending.pop()
        for name, path in index.items():
            if name in needed or not mentions(text, name, python_source=python_source):
                continue
            needed.add(name)
            pending.append((text_of(path), path.suffix == ".py"))
    return needed


def check_script_dependencies(skill_dir: Path, index: dict[str, Path]) -> None:
    """Fail the build if an installed script loads a sibling it does not carry."""
    for script in (skill_dir / "scripts").glob("*.py"):
        for sibling in sorted(script_loads(script.read_text(encoding="utf-8"))):
            if sibling in index and not (skill_dir / "scripts" / sibling).exists():
                sys.exit(
                    f"sync-skills: {skill_dir.name}/scripts/{script.name} needs {sibling}, "
                    "which was not copied"
                )


def build(out: Path) -> list[str]:
    """Write the flat skills tree into out. Returns the skill names written."""
    index = shared_index()
    names: list[str] = []
    for skill in skill_dirs():
        name = skill.name
        names.append(name)
        target = out / name
        for path in iter_files(skill):
            dest = target / path.relative_to(skill)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix in TEXT_SUFFIXES:
                text = path.read_text(encoding="utf-8")
                dest.write_text(UP_LINK.sub(r"\1/", text), encoding="utf-8")
            else:
                shutil.copy2(path, dest)
        for shared_name in sorted(shared_closure(skill, index)):
            source = index[shared_name]
            if skill in source.parents:
                continue  # the skill's own file was copied above
            dest = target / source.parent.name / source.name
            if dest.exists():
                sys.exit(f"sync-skills: {name} already has {dest.relative_to(out)}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if source.suffix in TEXT_SUFFIXES:
                dest.write_text(
                    UP_LINK.sub(r"\1/", source.read_text(encoding="utf-8")),
                    encoding="utf-8",
                )
            else:
                shutil.copy2(source, dest)
        check_script_dependencies(target, index)
    return names


def tree_entries(root: Path) -> set[Path]:
    """Every file and directory under root, with nothing skipped."""
    return {path.relative_to(root) for path in root.rglob("*")}


def tree_drift(built: Path, out: Path) -> list[str]:
    """Describe how out differs from a fresh build.

    The output side is compared without the source-side skips, so stale
    evaluation files, caches, .DS_Store, and leftover or empty skill
    directories in skills/ all count as drift: an installer would ship them.
    """
    expected = tree_entries(built)
    actual = tree_entries(out)
    drift = [f"missing: {rel}" for rel in sorted(expected - actual)]
    drift += [f"unexpected: {rel}" for rel in sorted(actual - expected)]
    for rel in sorted(expected & actual):
        left, right = built / rel, out / rel
        if left.is_dir() != right.is_dir():
            drift.append(f"type differs: {rel}")
        elif left.is_file() and not filecmp.cmp(left, right, shallow=False):
            drift.append(f"content differs: {rel}")
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="verify skills/ is up to date")
    args = parser.parse_args()

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            built = Path(tmp) / "skills"
            names = build(built)
            drift = tree_drift(built, OUT) if OUT.is_dir() else ["missing: skills/"]
            if drift:
                print(
                    "sync-skills: skills/ is out of date — run scripts/sync-skills.py",
                    file=sys.stderr,
                )
                for line in drift[:50]:
                    print(f"  {line}", file=sys.stderr)
                if len(drift) > 50:
                    print(f"  ... and {len(drift) - 50} more", file=sys.stderr)
                return 1
        print(f"skills/ is up to date ({len(names)} skills).")
        return 0

    # Rebuild from scratch so stale skills, evals, and caches never survive a sync.
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    names = build(OUT)
    print(f"Regenerated skills/ — {len(names)} skill(s) from src/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
