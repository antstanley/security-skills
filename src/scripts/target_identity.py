#!/usr/bin/env python3
"""Resolve the stable identity and content digest of a scan target."""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
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

# Repository config and attributes are untrusted. No probe below asks Git to read
# working-tree content, so clean and process filters, textconv, and external diff
# drivers never run; this helper hashes working-tree files itself. These overrides
# cover the remaining keys that could make a read-only probe start a program.
GIT_SAFE_CONFIG = (
    "core.fsmonitor=false",
    "log.showSignature=false",
)

SNAPSHOT_FORMAT = b"security-snapshot/v1"
# Each digest scheme is domain-separated so equal records never collide across kinds.
WORKTREE_SCHEME = b"git-worktree-changes/2"
LOCAL_PATCH_SCHEME = b"git-diff-local-patch/2"
REVISIONS_SCHEME = b"git-diff-revisions/2"
GITLINK_MODE = b"160000"
SYMLINK_MODE = b"120000"
OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    # A FIFO swapped in after lstat must not block the open.
    | getattr(os, "O_NONBLOCK", 0)
)

Record = tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class GitEntry:
    """One tree or index entry."""

    mode: bytes
    object_id: bytes


@dataclass(frozen=True)
class RepositorySettings:
    """Repository facts that change how Git compares working-tree files."""

    object_format: str
    file_mode: bool
    symlinks: bool


@dataclass(frozen=True)
class WorktreeState:
    """What a working-tree path holds, hashed without Git's content filters."""

    kind: str
    fields: Record
    git_mode: bytes = b""
    object_id: bytes = b""
    dirty: bool = False


def git_output(target: Path, *args: str) -> str | None:
    completed = git_command(target, *args, text=True)
    output = completed.stdout.strip()
    return output if completed.returncode == 0 and output else None


def git_bytes(target: Path, *args: str) -> bytes | None:
    completed = git_command(target, *args, text=False)
    return completed.stdout if completed.returncode == 0 else None


def git_command(
    target: Path,
    *args: str,
    text: bool,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    # Never refresh or rewrite the index of the repository under review.
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    command = ["git"]
    for setting in GIT_SAFE_CONFIG:
        command.extend(["-c", setting])
    full_command = [*command, "-C", str(target), *args]
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


def records_digest(scheme: bytes, records: tuple[Record, ...]) -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", SNAPSHOT_FORMAT)
    update_digest_field(digest, b"scheme", scheme)
    for record in records:
        for label, value in record:
            update_digest_field(digest, label, value)
    return f"security-snapshot/v1:sha256:{digest.hexdigest()}"


def split_nul(output: bytes) -> list[bytes]:
    return [item for item in output.split(b"\0") if item]


def hash_regular_file(
    path: Path, relative_path: str, object_format: str | None = None
) -> tuple[int, bytes, bytes]:
    """Return the size, SHA-256, and optional Git blob id of a regular file."""
    try:
        descriptor = os.open(path, OPEN_FLAGS)
    except OSError as exc:
        raise SystemExit(f"Could not read local file: {relative_path}") from exc
    try:
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise SystemExit(f"Local file changed type while hashing: {relative_path}")
            content_digest = hashlib.sha256()
            blob_digest = hashlib.new(object_format) if object_format else None
            if blob_digest is not None:
                blob_digest.update(b"blob %d\0" % metadata.st_size)
            content_size = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                content_digest.update(chunk)
                if blob_digest is not None:
                    blob_digest.update(chunk)
                content_size += len(chunk)
    except OSError as exc:
        raise SystemExit(f"Could not read local file: {relative_path}") from exc
    if blob_digest is not None and content_size != metadata.st_size:
        raise SystemExit(f"Local file changed while hashing: {relative_path}")
    blob_id = blob_digest.hexdigest().encode() if blob_digest is not None else b""
    return content_size, content_digest.digest(), blob_id


def git_blob_id(object_format: str, content: bytes) -> bytes:
    blob_digest = hashlib.new(object_format)
    blob_digest.update(b"blob %d\0" % len(content))
    blob_digest.update(content)
    return blob_digest.hexdigest().encode()


def special_file_kind(mode: int) -> bytes:
    """Name a non-regular file type; its content is never read."""
    if stat.S_ISFIFO(mode):
        return b"fifo"
    if stat.S_ISSOCK(mode):
        return b"socket"
    if stat.S_ISCHR(mode):
        return b"char-device"
    if stat.S_ISBLK(mode):
        return b"block-device"
    return b"special"


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


def nested_repository_root(path: Path) -> Path | None:
    """Return path when it is the top level of its own Git working tree."""
    try:
        (path / ".git").lstat()
    except OSError:
        return None
    root = git_output(path, "rev-parse", "--show-toplevel")
    try:
        if root is not None and Path(root).resolve() == path.resolve():
            return path.resolve()
    except OSError:
        return None
    return None


def head_revision(repository: Path) -> str | None:
    return git_output(repository, "rev-parse", "--verify", "--quiet", "HEAD")


@functools.cache
def repository_settings(repository: Path) -> RepositorySettings:
    object_format = git_output(repository, "rev-parse", "--show-object-format") or "sha1"
    if object_format not in {"sha1", "sha256"}:
        raise SystemExit(f"Unsupported Git object format: {object_format}")
    file_mode = git_output(repository, "config", "--type=bool", "--get", "core.fileMode")
    symlinks = git_output(repository, "config", "--type=bool", "--get", "core.symlinks")
    return RepositorySettings(
        object_format=object_format,
        file_mode=file_mode != "false",
        symlinks=symlinks != "false",
    )


def git_tree_entries(
    repository: Path, revision: str | None, pathspec: str
) -> dict[bytes, GitEntry]:
    if revision is None:
        # An unborn branch compares against the empty tree.
        return {}
    listed = git_bytes(repository, "ls-tree", "-r", "-z", revision, "--", pathspec)
    if listed is None:
        raise SystemExit("Could not list the files of the selected Git revision.")
    entries: dict[bytes, GitEntry] = {}
    for record in split_nul(listed):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, _, object_id = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit("Could not parse the selected Git revision.") from exc
        entries[raw_path] = GitEntry(mode, object_id)
    return entries


def git_index_entries(
    repository: Path, pathspec: str
) -> tuple[dict[bytes, dict[bytes, GitEntry]], set[bytes]]:
    """Return index entries by path and stage, plus sparse (skip-worktree) paths."""
    listed = git_bytes(repository, "ls-files", "-t", "--stage", "-z", "--", pathspec)
    if listed is None:
        raise SystemExit("Could not read the index of the selected Git working tree.")
    entries: dict[bytes, dict[bytes, GitEntry]] = {}
    skip_worktree: set[bytes] = set()
    for record in split_nul(listed):
        try:
            tag, metadata_and_path = record.split(b" ", 1)
            metadata, raw_path = metadata_and_path.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit("Could not parse the selected Git index.") from exc
        entries.setdefault(raw_path, {})[stage] = GitEntry(mode, object_id)
        if tag == b"S":
            skip_worktree.add(raw_path)
    return entries, skip_worktree


def git_untracked_paths(repository: Path, pathspec: str) -> list[bytes]:
    listed = git_bytes(
        repository, "ls-files", "--others", "--exclude-standard", "-z", "--", pathspec
    )
    if listed is None:
        raise SystemExit("Could not list untracked files in the selected Git working tree.")
    return sorted(split_nul(listed))


@functools.cache
def is_symlink(path: Path) -> bool:
    return path.is_symlink()


def observe_worktree_path(
    path: Path, relative_path: str, settings: RepositorySettings
) -> WorktreeState:
    """Describe one working-tree path by reading it directly, never through Git."""
    depth = len(Path(relative_path).parts) - 1
    if any(is_symlink(path.parents[level]) for level in range(depth)):
        # Like Git, treat a path behind a symlinked directory as absent rather than
        # reading through the link.
        return WorktreeState(kind="missing", fields=((b"kind", b"missing"),))
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return WorktreeState(kind="missing", fields=((b"kind", b"missing"),))
    except OSError as exc:
        raise SystemExit(f"Could not read local file: {relative_path}") from exc
    permissions = str(stat.S_IMODE(metadata.st_mode)).encode()
    if stat.S_ISLNK(metadata.st_mode):
        link_target = os.fsencode(os.readlink(path))
        return WorktreeState(
            kind="symlink",
            fields=((b"kind", b"symlink"), (b"mode", permissions), (b"content", link_target)),
            git_mode=SYMLINK_MODE,
            object_id=git_blob_id(settings.object_format, link_target),
        )
    if stat.S_ISREG(metadata.st_mode):
        size, content_sha256, blob_id = hash_regular_file(
            path, relative_path, settings.object_format
        )
        return WorktreeState(
            kind="file",
            fields=(
                (b"kind", b"file"),
                (b"mode", permissions),
                (b"size", str(size).encode()),
                (b"content-sha256", content_sha256),
            ),
            git_mode=b"100755" if metadata.st_mode & stat.S_IXUSR else b"100644",
            object_id=blob_id,
        )
    if stat.S_ISDIR(metadata.st_mode):
        nested = nested_repository_root(path)
        if nested is None:
            return WorktreeState(kind="directory", fields=((b"kind", b"directory"),))
        # Submodules and nested repositories are recorded by their checked-out
        # revision plus their own change digest, so dirty ones stay deterministic.
        nested_head = head_revision(nested)
        nested_changes = worktree_changes(nested, ".", nested_head)
        return WorktreeState(
            kind="repository",
            fields=(
                (b"kind", b"repository"),
                (b"head", nested_head.encode() if nested_head else b"unborn"),
                (b"changes", records_digest(WORKTREE_SCHEME, nested_changes).encode()),
            ),
            object_id=nested_head.encode() if nested_head else b"",
            dirty=bool(nested_changes),
        )
    kind = special_file_kind(metadata.st_mode)
    return WorktreeState(kind=kind.decode(), fields=((b"kind", kind), (b"mode", permissions)))


def worktree_matches(
    worktree: WorktreeState,
    entry: GitEntry,
    settings: RepositorySettings,
    *,
    skip_worktree: bool,
) -> bool:
    """Return whether the working tree holds exactly the content of an index entry."""
    if skip_worktree and worktree.kind == "missing":
        return True
    if entry.mode == GITLINK_MODE:
        if worktree.kind == "directory":
            # An uninitialized submodule is an empty directory, as Git treats it.
            return True
        return (
            worktree.kind == "repository"
            and worktree.object_id == entry.object_id
            and not worktree.dirty
        )
    if entry.mode == SYMLINK_MODE:
        # Without core.symlinks, Git checks a link out as a file holding its target.
        if worktree.kind == "symlink" or (not settings.symlinks and worktree.kind == "file"):
            return worktree.object_id == entry.object_id
        return False
    if worktree.kind != "file" or worktree.object_id != entry.object_id:
        return False
    return not settings.file_mode or worktree.git_mode == entry.mode


def entry_field(entry: GitEntry | None) -> bytes:
    return b"absent" if entry is None else entry.mode + b" " + entry.object_id


@functools.cache
def worktree_changes(
    repository: Path, pathspec: str, base_revision: str | None
) -> tuple[Record, ...]:
    """Return every index or working-tree change from base_revision, in path order.

    A path is recorded with its base entry, index stages, and working-tree state when
    the index or the working tree differs from the base. Untracked, non-ignored paths
    are recorded in full. Files are compared by their raw bytes, so a repository whose
    filters or line-ending rules rewrite content reports those files as changed.
    """
    settings = repository_settings(repository)
    base = git_tree_entries(repository, base_revision, pathspec)
    index, skip_worktree = git_index_entries(repository, pathspec)
    records: list[Record] = []
    for raw_path in sorted(set(base) | set(index)):
        base_entry = base.get(raw_path)
        stages = index.get(raw_path, {})
        staged = stages.get(b"0")
        relative_path = os.fsdecode(raw_path)
        worktree = observe_worktree_path(repository / relative_path, relative_path, settings)
        if (
            staged is not None
            and len(stages) == 1
            and staged == base_entry
            and worktree_matches(
                worktree, staged, settings, skip_worktree=raw_path in skip_worktree
            )
        ):
            continue
        fields: list[tuple[bytes, bytes]] = [
            (b"path", raw_path),
            (b"base", entry_field(base_entry)),
        ]
        for stage in sorted(stages):
            fields.append((b"index-stage-" + stage, entry_field(stages[stage])))
        fields.extend(worktree.fields)
        records.append(tuple(fields))
    for raw_path in git_untracked_paths(repository, pathspec):
        # Git lists an untracked nested repository once, with a trailing slash.
        raw_path = raw_path.rstrip(b"/")
        relative_path = os.fsdecode(raw_path)
        worktree = observe_worktree_path(repository / relative_path, relative_path, settings)
        records.append(((b"untracked-path", raw_path), *worktree.fields))
    return tuple(records)


def worktree_content_digest(target: Path) -> str:
    repository, pathspec = git_worktree_context(target)
    changes = worktree_changes(repository, pathspec, head_revision(repository))
    return records_digest(WORKTREE_SCHEME, changes)


def clean_worktree_content_digest() -> str:
    return records_digest(WORKTREE_SCHEME, ())


def resolve_commit(repository: Path, value: str, option: str) -> str:
    if not value or value.startswith("-"):
        raise SystemExit(f"{option} must name a Git revision.")
    resolved = git_output(repository, "rev-parse", "--verify", "--quiet", f"{value}^{{commit}}")
    if resolved is None:
        raise SystemExit(f"Could not resolve {option} to a commit: {value}")
    return resolved


def revisions_diff_digest(repository: Path, pathspec: str, base: str, head: str) -> str:
    """Hash the tree-to-tree change set from base to head.

    The raw records name the mode and object id on each side of every changed path,
    which pins the reviewed content without depending on diff formatting settings.
    """
    listed = git_bytes(
        repository, "diff-tree", "-r", "-z", "--no-renames", base, head, "--", pathspec
    )
    if listed is None:
        raise SystemExit("Could not compare the selected Git revisions.")
    fields = listed.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    if len(fields) % 2:
        raise SystemExit("Could not parse the selected Git revision diff.")
    records = sorted(
        ((b"path", fields[index + 1]), (b"change", fields[index]))
        for index in range(0, len(fields), 2)
    )
    return records_digest(REVISIONS_SCHEME, tuple(records))


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
    for raw_path in split_nul(listed):
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
    update_digest_field(digest, b"format", SNAPSHOT_FORMAT)
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
            content_size, content_sha256, _ = hash_regular_file(path, str(relative_path))
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_sha256)
        else:
            # FIFOs, sockets, and devices are recorded by type; reading them could
            # block or have side effects.
            update_digest_field(digest, b"kind", special_file_kind(metadata.st_mode))
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
                "commitSubject": git_output(
                    target, "show", "--no-show-signature", "-s", "--format=%s", "HEAD"
                ),
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
    repository, pathspec = git_worktree_context(target)
    head = head_revision(repository)
    if head is None:
        # An unborn branch has no immutable revision to name.
        return "git_worktree"
    return "git_worktree" if worktree_changes(repository, pathspec, head) else "git_revision"


def describe_target(
    target: Path,
    kind: str | None,
    *,
    base: str | None = None,
    head: str | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
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
    if resolved_kind == "git_diff":
        if base is None:
            raise SystemExit("--kind git_diff requires --base.")
        repository, pathspec = git_worktree_context(resolved)
        base_revision = resolve_commit(repository, base, "--base")
        if mode == "local-patch":
            # The reviewed head is the working tree: staged, unstaged, and untracked
            # changes on top of the base.
            changes = worktree_changes(repository, pathspec, base_revision)
            described["revision"] = git_revision(resolved)
            described["snapshotDigest"] = records_digest(LOCAL_PATCH_SCHEME, changes)
            described["baseRevision"] = base_revision
        else:
            head_commit = resolve_commit(repository, head or "HEAD", "--head")
            described["revision"] = head_commit
            described["snapshotDigest"] = revisions_diff_digest(
                repository, pathspec, base_revision, head_commit
            )
            described["baseRevision"] = base_revision
            described["headRevision"] = head_commit
        described["git"] = git_target_metadata(resolved)
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
    parser.add_argument(
        "--base",
        help=(
            "git_diff only, required: the diff base revision. The digest covers a direct "
            "(two-dot) comparison from this commit, so pass the merge-base for branch and "
            "pull request comparisons"
        ),
    )
    parser.add_argument(
        "--head",
        help="git_diff revisions mode only: the diff head revision (default: HEAD)",
    )
    parser.add_argument(
        "--mode",
        choices=("revisions", "local-patch"),
        help=(
            "git_diff only: compare --base with --head (revisions, the default) or with "
            "the working tree, including staged and untracked files (local-patch)"
        ),
    )
    args = parser.parse_args()
    if args.kind != "git_diff":
        if args.base is not None or args.head is not None or args.mode is not None:
            parser.error("--base, --head, and --mode apply only to --kind git_diff")
    elif args.base is None:
        parser.error("--kind git_diff requires --base")
    elif args.mode == "local-patch" and args.head is not None:
        parser.error("--head does not apply to --mode local-patch")
    return args


def main() -> int:
    args = parse_args()
    try:
        described = describe_target(
            args.target, args.kind, base=args.base, head=args.head, mode=args.mode
        )
    except OSError as exc:
        print(f"target_identity.py: error: {exc}", file=sys.stderr)
        return 2
    json.dump(described, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
