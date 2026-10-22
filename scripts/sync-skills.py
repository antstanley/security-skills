#!/usr/bin/env python3
"""Generate the installable, self-contained skills/ tree from src/.

src/ is the canonical source. Each skill under src/skills/<name>/ is copied to
skills/<name>/ together with the shared references, scripts, and schemas it
needs, so every skill folder works on its own. That matters because installers
(the Vercel `skills` CLI, install.sh, a manual copy) move a single skill
directory and nothing else.

Shared files are included when a skill's text (or the text of another included
shared file) mentions their file name. Links written as `../../references/x.md`
are rewritten to `references/x.md` so they resolve inside the copied folder.

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


def mentions(text: str, name: str) -> bool:
    """Whether text refers to a shared file.

    Scripts are often referenced by module name rather than file name
    (`from rank_preview import ...`, `_load_script("validate_report_format")`),
    so a Python file also matches on its stem as a whole word.
    """
    if name in text:
        return True
    if name.endswith(".py"):
        stem = re.escape(name[: -len(".py")])
        return re.search(rf"(?<!\w){stem}(?!\w)", text) is not None
    return False


def shared_closure(skill: Path, index: dict[str, Path]) -> set[str]:
    """Return the shared file names a skill needs, following mentions transitively."""
    corpus = [text_of(p) for p in iter_files(skill)]
    needed: set[str] = set()
    pending = list(corpus)
    while pending:
        text = pending.pop()
        for name, path in index.items():
            if name in needed or not mentions(text, name):
                continue
            needed.add(name)
            pending.append(text_of(path))
    return needed


# Imports and by-name loads that a copied script must be able to satisfy.
SCRIPT_DEPENDENCY = re.compile(
    r"^(?:from|import) (\w+)|_load_script\(\"(\w+)\"\)|\"(\w+)\.py\"", re.MULTILINE
)


def check_script_dependencies(skill_dir: Path, index: dict[str, Path]) -> None:
    """Fail the build if an installed script names a sibling it does not carry."""
    for script in (skill_dir / "scripts").glob("*.py"):
        for match in SCRIPT_DEPENDENCY.finditer(script.read_text(encoding="utf-8")):
            module = next(group for group in match.groups() if group)
            sibling = f"{module}.py"
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


def same_tree(a: Path, b: Path) -> bool:
    """Compare two trees file by file, ignoring cache directories."""
    left = {p.relative_to(a) for p in iter_files(a)}
    right = {p.relative_to(b) for p in iter_files(b)}
    if left != right:
        return False
    return all(filecmp.cmp(a / rel, b / rel, shallow=False) for rel in left)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="verify skills/ is up to date")
    args = parser.parse_args()

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            built = Path(tmp) / "skills"
            names = build(built)
            if not OUT.is_dir() or not same_tree(built, OUT):
                print("sync-skills: skills/ is out of date — run scripts/sync-skills.py", file=sys.stderr)
                return 1
        print(f"skills/ is up to date ({len(names)} skills).")
        return 0

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    names = build(OUT)
    print(f"Regenerated skills/ — {len(names)} skill(s) from src/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
