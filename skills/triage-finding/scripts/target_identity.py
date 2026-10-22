#!/usr/bin/env python3
"""Resolve the stable identity and content digest of a scan target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

# Ambient Git environment variables would silently redirect every probe below.
GIT_REPOSITORY_ENVIRONMENT = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)


def git_output(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str | None:
    completed = git_command(target, *args, text=True, git_dir=git_dir, work_tree=work_tree)
    output = completed.stdout.strip()
    return output if completed.returncode == 0 and output else None


def git_bytes(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> bytes | None:
    completed = git_command(target, *args, text=False, git_dir=git_dir, work_tree=work_tree)
    return completed.stdout if completed.returncode == 0 else None


def git_command(
    target: Path,
    *args: str,
    text: bool,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    if (git_dir is None) != (work_tree is None):
        raise ValueError("git_dir and work_tree must be provided together")
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    # Repository-local config is untrusted; fsmonitor may name an executable hook.
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(target)]
    if git_dir is not None and work_tree is not None:
        command.extend(["--git-dir", str(git_dir), "--work-tree", str(work_tree)])
    full_command = [*command, *args]
    try:
        if text:
            # Decode UTF-8 explicitly; the Windows ANSI codepage breaks
            # non-ASCII output.
            return subprocess.run(
                full_command,
                check=False,
                capture_output=True,
                env=environment,
                encoding="utf-8",
                errors="replace",
            )
        return subprocess.run(
            full_command,
            check=False,
            capture_output=True,
            env=environment,
        )
    except FileNotFoundError:
        # Git is optional for directory scans. Treat an unavailable executable like
        # any other failed Git probe so the target falls back to a directory snapshot.
        empty_output = "" if text else b""
        return subprocess.CompletedProcess(full_command, 127, empty_output, empty_output)


def update_digest_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def worktree_content_digest(target: Path) -> str:
    require_clean_submodule_worktrees(target)
    repository, pathspec = git_worktree_context(target)
    return worktree_content_digest_for_context(repository, pathspec)


def worktree_content_digest_for_context(
    repository: Path,
    pathspec: str,
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str:
    tracked = git_bytes(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "HEAD",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    untracked = git_bytes(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    if tracked is None or untracked is None:
        raise SystemExit("Could not snapshot the selected working-tree changes.")
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", tracked)
    for raw_path in sorted(path for path in untracked.split(b"\0") if path):
        relative_path = os.fsdecode(raw_path)
        path = (work_tree or repository) / relative_path
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
        update_digest_field(digest, b"untracked-path", raw_path)
        update_digest_field(
            digest,
            b"untracked-mode",
            str(stat.S_IMODE(metadata.st_mode)).encode(),
        )
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"symlink")
            update_digest_field(
                digest,
                b"untracked-content",
                os.fsencode(os.readlink(path)),
            )
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
            update_digest_field(digest, b"untracked-kind", b"file")
            update_digest_field(
                digest,
                b"untracked-size",
                str(content_size).encode(),
            )
            update_digest_field(
                digest,
                b"untracked-content-sha256",
                content_digest.digest(),
            )
        else:
            raise SystemExit(f"Unsupported untracked file type: {relative_path}")
    return f"security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_worktree_context(target: Path) -> tuple[Path, str]:
    root = git_output(target, "rev-parse", "--show-toplevel")
    if root is None:
        raise SystemExit("Could not inspect the selected Git working tree.")
    repository = Path(root).resolve()
    try:
        relative = target.resolve().relative_to(repository)
    except ValueError as exc:
        raise SystemExit("Scan target must stay inside its Git working tree.") from exc
    return repository, relative.as_posix() or "."


def git_submodule_entries(target: Path) -> tuple[tuple[Path, str], ...]:
    repository, pathspec = git_worktree_context(target)
    staged = git_bytes(repository, "ls-files", "--stage", "-z", "--", pathspec)
    if staged is None:
        raise SystemExit("Could not inspect Git submodules in the selected working tree.")
    entries = []
    for record in (item for item in staged.split(b"\0") if item):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, _ = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit(
                "Could not inspect Git submodules in the selected working tree."
            ) from exc
        if mode != b"160000":
            continue
        entries.append((repository / os.fsdecode(raw_path), object_id.decode("ascii")))
    return tuple(entries)


def git_submodule_paths(target: Path) -> tuple[Path, ...]:
    return tuple(path for path, _ in git_submodule_entries(target))


def require_clean_submodule_worktrees(target: Path) -> None:
    for submodule, expected_revision in git_submodule_entries(target):
        relative_path = str(submodule.relative_to(target))
        if not submodule.exists():
            continue
        try:
            (submodule / ".git").lstat()
        except FileNotFoundError:
            continue
        root = git_output(submodule, "rev-parse", "--show-toplevel")
        try:
            is_initialized = root is not None and Path(root).resolve() == submodule.resolve()
        except OSError:
            is_initialized = False
        if not is_initialized:
            raise SystemExit(
                f"Could not inspect initialized Git submodule contents: {relative_path}"
            )
        if git_output(submodule, "rev-parse", "HEAD") != expected_revision:
            raise SystemExit(
                "Initialized Git submodules must be checked out at the revision recorded "
                f"by the parent repository: {relative_path}"
            )
        status = git_bytes(
            submodule,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        if status is None:
            raise SystemExit(f"Could not inspect Git submodule contents: {relative_path}")
        if status:
            raise SystemExit(
                f"Dirty Git submodules are not supported for remediation integrity checks: {relative_path}"
            )
        require_clean_submodule_worktrees(submodule)


def clean_worktree_content_digest() -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", b"")
    return f"security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_directory_snapshot_paths(target: Path) -> list[Path] | None:
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None:
        return None
    repository, pathspec = git_worktree_context(target)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    paths: list[Path] = []
    for raw_path in (raw_path for raw_path in listed.split(b"\0") if raw_path):
        path = repository / os.fsdecode(raw_path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # The index can retain a path that was staged and then deleted.
            continue
        paths.append(path)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        nested_repository_root = git_output(path, "rev-parse", "--show-toplevel")
        if (
            nested_repository_root is not None
            and Path(nested_repository_root).resolve() == path.resolve()
        ):
            nested_paths = git_directory_snapshot_paths(path)
            if nested_paths is not None:
                paths.extend(nested_paths)
                continue
        paths.extend(
            nested_path
            for nested_path in path.rglob("*")
            if ".git" not in nested_path.relative_to(path).parts
        )
    return sorted(set(paths))


def directory_content_digest(target: Path, *, excluded: tuple[Path, ...] = ()) -> str:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(target))
        except ValueError:
            continue
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    digest = hashlib.sha256()
    # Domain separation: the emitted identifier is part of the digest material.
    update_digest_field(digest, b"format", b"security-snapshot/v1")
    for path in paths:
        relative_path = path.relative_to(target)
        if any(
            relative_path == excluded_path or excluded_path in relative_path.parents
            for excluded_path in excluded_relative
        ):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read local file: {relative_path}") from exc
        raw_path = os.fsencode(relative_path.as_posix())
        update_digest_field(digest, b"path", raw_path)
        update_digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode())
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read local file: {relative_path}") from exc
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise SystemExit(f"Unsupported local file type: {relative_path}")
    return f"security-snapshot/v1:sha256:{digest.hexdigest()}"


def directory_snapshot_regular_file_count(target: Path) -> int:
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    count = 0
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not inspect local file: {path.relative_to(target)}") from exc
        if stat.S_ISREG(metadata.st_mode):
            count += 1
    return count


def git_revision(target: Path) -> str:
    return git_output(target, "rev-parse", "HEAD") or "unversioned"


def git_target_metadata(target: Path) -> dict[str, Any]:
    is_git = git_output(target, "rev-parse", "--git-dir") is not None
    is_worktree = git_output(target, "rev-parse", "--is-inside-work-tree") == "true"
    revision = git_output(target, "rev-parse", "--verify", "HEAD")
    repository_root = git_output(target, "rev-parse", "--show-toplevel") if is_worktree else None
    supported = (
        is_git
        and is_worktree
        and revision is not None
        and repository_root is not None
        and Path(repository_root).resolve() == target
    )
    metadata: dict[str, Any] = {
        "hasHead": revision is not None,
        "isGit": is_git,
        "isWorktree": is_worktree,
        "reviewChangesSupported": supported,
    }
    if not is_git:
        return metadata
    branch = git_output(target, "symbolic-ref", "--quiet", "--short", "HEAD")
    metadata.update({"branch": branch, "detachedHead": revision is not None and branch is None})
    if revision is not None:
        metadata.update(
            {
                "commitSubject": git_output(target, "show", "-s", "--format=%s", "HEAD"),
                "revision": revision,
                "shortRevision": revision[:7],
            }
        )
    return metadata


def stable_target_id(target: Path) -> str:
    """Return a stable identity for a local scan target."""
    remote = git_output(target, "config", "--get", "remote.origin.url")
    if remote is not None:
        sanitized = sanitize_remote_url(remote)
        if sanitized is not None:
            digest = hashlib.sha256(f"remote\0{sanitized}".encode()).hexdigest()
            return f"target_sha256_{digest}"
    digest = hashlib.sha256(f"local-workspace\0{target}".encode()).hexdigest()
    return f"target_sha256_{digest}"


def sanitize_remote_url(remote: str) -> str | None:
    """Strip credentials, query, and fragment from a remote URL, or return None."""
    from urllib.parse import urlsplit, urlunsplit

    candidate = remote.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        # scp-style syntax such as git@github.com:owner/repo.git
        user, separator, rest = candidate.partition("@")
        if not separator or ":" not in rest:
            return None
        host, _, path = rest.partition(":")
        return f"ssh://{host}/{path.lstrip('/')}"
    parts = urlsplit(candidate)
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        # A malformed port (for example ssh://git@host:owner/repo.git) makes
        # the remote unusable; drop it so the caller falls back to the
        # local-workspace identity.
        return None
    if not hostname:
        return None
    netloc = hostname
    if port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def resolve_target_kind(target: Path) -> str:
    """Classify the target the way the scan contract expects."""
    if git_output(target, "rev-parse", "--is-inside-work-tree") != "true":
        return "directory_snapshot"
    status = git_bytes(target, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status is None:
        return "directory_snapshot"
    return "git_worktree" if status else "git_revision"


def describe_target(target: Path, kind: str | None) -> dict[str, Any]:
    """Return the scan-contract target fields for a resolved directory."""
    resolved = target.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise SystemExit(f"Scan target is not a directory: {resolved}")
    resolved_kind = kind or resolve_target_kind(resolved)
    described: dict[str, Any] = {
        "kind": resolved_kind,
        "targetId": stable_target_id(resolved),
        "path": str(resolved),
    }
    if resolved_kind == "directory_snapshot":
        described["snapshotDigest"] = directory_content_digest(resolved)
        return described
    described["revision"] = git_revision(resolved)
    if resolved_kind == "git_revision":
        described["snapshotDigest"] = clean_worktree_content_digest()
    else:
        described["snapshotDigest"] = worktree_content_digest(resolved)
    described["git"] = git_target_metadata(resolved)
    return described


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path, help="scan target directory")
    parser.add_argument(
        "--kind",
        choices=("git_worktree", "git_revision", "git_diff", "directory_snapshot"),
        help="force a target kind instead of detecting it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        described = describe_target(args.target, args.kind)
    except OSError as exc:
        print(f"target_identity.py: error: {exc}", file=sys.stderr)
        return 2
    json.dump(described, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
