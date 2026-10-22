#!/usr/bin/env python3
"""Check that the host can honestly run a security scan workflow."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Severity = Literal["block", "warn", "suggest"]
CheckStatus = Literal["pass", "fail", "unknown"]

PHASE_SKILLS = (
    "threat-model",
    "finding-discovery",
    "validation",
    "attack-path-analysis",
)

# The diff and deep tails mandate a write-up per reportable finding and one
# hardening pass, so those profiles cannot complete without these skills.
TAIL_SKILLS = (
    "vulnerability-writeup",
    "propose-security-hardening",
)

DEEP_SCAN_MIN_WORKERS = 4

# Runtime facts the profiles evaluate. An unknown name is almost always a typo that
# would otherwise leave a capability silently unreported.
RUNTIME_CHECKS = ("delegation_available",)

# Ambient Git environment variables would silently redirect the repository
# probe below to another repository, so strip them the way target_identity.py
# does.
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


@dataclass(frozen=True)
class Profile:
    """A named set of capability requirements for one scan mode."""

    description: str
    required_skills: tuple[str, ...]
    requires_git: bool = False
    delegation: Severity = "suggest"
    min_worker_slots: int = 0
    min_worker_slots_severity: Severity = "warn"


PROFILES: dict[str, Profile] = {
    "security_scan": Profile(
        description="Repository or scoped-path security scan.",
        required_skills=PHASE_SKILLS,
        delegation="suggest",
    ),
    "security_diff_scan": Profile(
        description="Git-backed security diff scan.",
        required_skills=(*PHASE_SKILLS, *TAIL_SKILLS),
        requires_git=True,
        delegation="suggest",
    ),
    "deep_security_scan": Profile(
        description="Repeated-discovery deep security scan.",
        required_skills=(*PHASE_SKILLS, *TAIL_SKILLS, "security-scan"),
        delegation="block",
        min_worker_slots=DEEP_SCAN_MIN_WORKERS,
        min_worker_slots_severity="warn",
    ),
}


@dataclass
class Result:
    """One evaluated capability requirement."""

    capability: str
    status: CheckStatus
    severity: Severity
    reason: str
    remediation: str | None = None

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "capability": self.capability,
            "status": self.status,
            "severity": self.severity,
            "reason": self.reason,
        }
        if self.remediation is not None:
            payload["remediation"] = self.remediation
        return payload


@dataclass
class Report:
    """The full preflight outcome for one profile."""

    profile: str
    results: list[Result] = field(default_factory=list)
    resolved: dict[str, object] = field(default_factory=dict)

    def status(self) -> str:
        blocking = [item for item in self.results if item.severity == "block"]
        if any(item.status == "fail" for item in blocking):
            return "blocked"
        if any(item.status == "unknown" for item in blocking):
            return "incomplete"
        return "ready"

    def to_json(self) -> dict[str, object]:
        return {
            "status": self.status(),
            "profile": self.profile,
            "results": [item.to_json() for item in self.results],
            "resolved": self.resolved,
        }


def python_command() -> str:
    """Return the interpreter a skill should use for later helper commands."""
    configured = os.environ.get("PYTHON")
    if configured:
        return configured
    return sys.executable or ("python" if os.name == "nt" else "python3")


def state_dir() -> Path:
    """Return the configured directory holding durable state, before resolving links."""
    configured = os.environ.get("SECURITY_STATE_DIR")
    if configured:
        return Path(configured).expanduser().absolute()
    state_home = os.environ.get("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return (root / "security-skills").absolute()


def scan_root() -> Path:
    """Return the configured directory for scan bundles, before resolving links."""
    configured = os.environ.get("SECURITY_SCAN_ROOT")
    if configured:
        return Path(configured).expanduser().absolute()
    return (Path(tempfile.gettempdir()) / "security-scans").absolute()


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def unsafe_ownership(configured: Path, resolved: Path) -> str | None:
    """Return why another local user could plant or swap files under a directory."""
    # Windows ACLs do not map onto POSIX owners and mode bits.
    if os.name == "nt":
        return None
    user = os.geteuid()
    try:
        link = configured.lstat()
        # Another user could repoint their own symlink later; root's links are trusted.
        if stat.S_ISLNK(link.st_mode) and link.st_uid not in {user, 0}:
            return f"{configured} is a symlink owned by another user (uid {link.st_uid})."
        metadata = resolved.stat()
    except OSError as exc:
        return f"Could not inspect {resolved}: {exc.strerror or exc}"
    if not stat.S_ISDIR(metadata.st_mode):
        return f"{resolved} is not a directory."
    if metadata.st_uid != user:
        return f"{resolved} is owned by another user (uid {metadata.st_uid})."
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{resolved} is writable by other users (mode {stat.S_IMODE(metadata.st_mode):o})."
    return None


def create_private_directory(path: Path) -> None:
    """Create path for the current user only; leave an existing directory alone."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return
    if os.name != "nt":
        # Pin the mode in case the umask removed owner bits.
        path.chmod(0o700)


def directory_is_writable(path: Path) -> bool:
    """Return whether a scan can create and remove files under path."""
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix=".preflight-", delete=True):
            return True
    except OSError:
        return False


def git_repo_root(target: Path) -> str | None:
    """Return the Git working-tree root containing target, if any."""
    if shutil.which("git") is None:
        return None
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    try:
        completed = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            timeout=30,
            env=environment,
            # Decode UTF-8 explicitly; the Windows ANSI codepage breaks
            # non-ASCII paths.
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    root = completed.stdout.strip()
    return root or None


def check_target(target: Path, report: Report) -> Path | None:
    """Record whether the resolved scan target is usable."""
    try:
        resolved = target.expanduser().resolve(strict=True)
    except OSError:
        report.results.append(
            Result(
                capability="scan_target",
                status="fail",
                severity="block",
                reason=f"Scan target does not exist: {target}",
                remediation="Ask the user for a path that exists on this host.",
            )
        )
        return None
    if not resolved.is_dir():
        report.results.append(
            Result(
                capability="scan_target",
                status="fail",
                severity="block",
                reason=f"Scan target is not a directory: {resolved}",
                remediation="Pass the containing directory as the scan target.",
            )
        )
        return None
    report.results.append(
        Result(
            capability="scan_target",
            status="pass",
            severity="block",
            reason=f"Scan target resolved to {resolved}",
        )
    )
    return resolved


def check_skills(profile: Profile, available: set[str], report: Report) -> None:
    """Record whether every phase skill this profile needs is installed."""
    if not available:
        report.results.append(
            Result(
                capability="phase_skills",
                status="unknown",
                severity="block",
                reason="No available skills were reported to the preflight.",
                remediation=(
                    "Rerun with one --available-skill argument per installed security "
                    "skill, taken from the session's skill list."
                ),
            )
        )
        return
    missing = sorted(set(profile.required_skills) - available)
    if missing:
        report.results.append(
            Result(
                capability="phase_skills",
                status="fail",
                severity="block",
                reason=f"Missing required security skills: {', '.join(missing)}",
                remediation="Install the phase skills of this security skill set.",
            )
        )
        return
    report.results.append(
        Result(
            capability="phase_skills",
            status="pass",
            severity="block",
            reason=f"All required phase skills are available: {', '.join(profile.required_skills)}",
        )
    )


def check_delegation(profile: Profile, delegation: bool | None, report: Report) -> None:
    """Record whether subagent delegation is available for this profile."""
    if delegation is None:
        report.results.append(
            Result(
                capability="delegated_workers",
                status="unknown",
                severity=profile.delegation,
                reason="Subagent delegation availability was not reported.",
                remediation=(
                    "Inspect your harness's tools for a way to start a subagent and rerun with "
                    "--runtime-check delegation_available=true|false."
                ),
            )
        )
        return
    if delegation:
        report.results.append(
            Result(
                capability="delegated_workers",
                status="pass",
                severity=profile.delegation,
                reason="A delegation mechanism is available for subagent review workers.",
            )
        )
        return
    report.results.append(
        Result(
            capability="delegated_workers",
            status="fail",
            severity=profile.delegation,
            reason="Subagent delegation is unavailable; the parent must run every phase itself.",
            remediation=(
                "Enable subagent delegation for this session, or run security-scan instead."
                if profile.delegation == "block"
                else "Continue on the documented single-thread fallback, or enable subagent "
                "tool for this session."
            ),
        )
    )


def check_worker_slots(profile: Profile, slots: int | None, report: Report) -> None:
    """Record whether enough concurrent workers are available."""
    if profile.min_worker_slots <= 0:
        return
    capability = f"usable_worker_slots_{profile.min_worker_slots}"
    if slots is None:
        report.results.append(
            Result(
                capability=capability,
                status="unknown",
                severity=profile.min_worker_slots_severity,
                reason="Concurrent worker capacity was not reported.",
                remediation="Rerun with --worker-slots <count> once capacity is known.",
            )
        )
        return
    if slots >= profile.min_worker_slots:
        report.results.append(
            Result(
                capability=capability,
                status="pass",
                severity=profile.min_worker_slots_severity,
                reason=f"{slots} concurrent workers are available.",
            )
        )
        return
    report.results.append(
        Result(
            capability=capability,
            status="fail",
            severity=profile.min_worker_slots_severity,
            reason=(
                f"Only {slots} concurrent workers are available; "
                f"{profile.min_worker_slots} give better variance reduction."
            ),
            remediation="Continue with fewer discovery passes and say so in the scan summary.",
        )
    )


def check_git(profile: Profile, target: Path | None, report: Report) -> str | None:
    """Record whether the target sits inside a usable Git working tree."""
    if not profile.requires_git:
        return None
    if target is None:
        return None
    if shutil.which("git") is None:
        report.results.append(
            Result(
                capability="git_available",
                status="fail",
                severity="block",
                reason="git was not found on PATH.",
                remediation="Install Git, or run a repository scan instead of a diff scan.",
            )
        )
        return None
    root = git_repo_root(target)
    if root is None:
        report.results.append(
            Result(
                capability="git_repository",
                status="fail",
                severity="block",
                reason=f"{target} is not inside a Git working tree.",
                remediation="Run a repository or scoped-path scan instead of a diff scan.",
            )
        )
        return None
    report.results.append(
        Result(
            capability="git_repository",
            status="pass",
            severity="block",
            reason=f"Git working tree root is {root}",
        )
    )
    return root


def resolve_repository(target: Path | None) -> tuple[Path | None, str | None, str | None]:
    """Return the repository root, its kind, and the target's repo-relative scope."""
    if target is None:
        return None, None, None
    root = git_repo_root(target)
    if root is not None:
        try:
            repository = Path(root).resolve(strict=True)
            scope = target.relative_to(repository).as_posix() or "."
        except (OSError, ValueError):
            # A toplevel that does not contain the target (for example through
            # core.worktree) is not a usable repository root for this scan.
            pass
        else:
            return repository, "git", scope
    return target, "directory", "."


def check_private_directory(
    label: str,
    variable: str,
    configured: Path,
    protected: tuple[Path, ...],
    report: Report,
) -> Path:
    """Record whether scan output can live privately under a directory outside the target."""
    resolved = configured.resolve()

    def fail(reason: str, remediation: str) -> Path:
        report.results.append(
            Result(
                capability=label,
                status="fail",
                severity="block",
                reason=reason,
                remediation=remediation,
            )
        )
        return resolved

    # Check containment before creating anything, so a misconfigured root never
    # becomes a new directory inside the repository under review.
    for root in protected:
        if is_within(resolved, root):
            return fail(
                f"{resolved} is inside the scan target or its repository ({root}).",
                f"Set {variable} to a directory outside {root}; scan output must never be "
                "written into the repository under review.",
            )
    try:
        create_private_directory(resolved)
    except OSError as exc:
        return fail(
            f"Could not create {resolved}: {exc.strerror or exc}",
            f"Set {variable} to a writable directory owned by the current user.",
        )
    problem = unsafe_ownership(configured, resolved)
    if problem is not None:
        return fail(
            problem,
            f"Set {variable} to a directory owned by the current user that other users cannot "
            "write to, or fix the ownership and mode (chmod 700) of this one.",
        )
    if not directory_is_writable(resolved):
        return fail(
            f"{resolved} is not writable.",
            f"Set {variable} to a writable directory owned by the current user.",
        )
    report.results.append(
        Result(
            capability=label,
            status="pass",
            severity="block",
            reason=f"{resolved} is writable and private to the current user.",
        )
    )
    return resolved


def parse_runtime_check(value: str) -> tuple[str, bool]:
    """Parse a name=true|false runtime fact."""
    name, separator, raw = value.partition("=")
    if not separator or raw not in {"true", "false"}:
        raise argparse.ArgumentTypeError(f"runtime check must be <name>=true|false, got: {value}")
    if name not in RUNTIME_CHECKS:
        raise argparse.ArgumentTypeError(
            f"unknown runtime check {name!r}; expected one of: {', '.join(RUNTIME_CHECKS)}"
        )
    return name, raw == "true"


def worker_slot_count(value: str) -> int:
    """Parse a non-negative worker-slot count."""
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"worker slots must be an integer, got: {value}") from None
    if count < 0:
        raise argparse.ArgumentTypeError(f"worker slots must not be negative, got: {value}")
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--target", type=Path, default=Path.cwd(), help="scan target directory")
    parser.add_argument(
        "--available-skill",
        action="append",
        default=[],
        dest="available_skills",
        help="skill name of an installed security skill; repeatable",
    )
    parser.add_argument(
        "--runtime-check",
        action="append",
        default=[],
        type=parse_runtime_check,
        dest="runtime_checks",
        help=f"runtime fact as <name>=true|false; known names: {', '.join(RUNTIME_CHECKS)}",
    )
    parser.add_argument(
        "--worker-slots",
        type=worker_slot_count,
        help="number of concurrent subagents this session can run (0 or more)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = PROFILES[args.profile]
    report = Report(profile=args.profile)

    runtime = dict(args.runtime_checks)
    target = check_target(args.target, report)
    check_skills(profile, set(args.available_skills), report)
    check_delegation(profile, runtime.get("delegation_available"), report)
    check_worker_slots(profile, args.worker_slots, report)
    check_git(profile, target, report)
    repo_root, repo_kind, scope = resolve_repository(target)

    protected = tuple(path for path in (target, repo_root) if path is not None)
    scans = check_private_directory(
        "scan_root_writable", "SECURITY_SCAN_ROOT", scan_root(), protected, report
    )
    state = check_private_directory(
        "state_dir_writable", "SECURITY_STATE_DIR", state_dir(), protected, report
    )
    # Name the scan folder after the repository root, not a scoped subfolder, so every
    # scan of one repository shares its folder and threat model instead of colliding
    # with other repositories on a common folder name such as "src".
    repo_name = (repo_root.name if repo_root is not None else "") or "repository"

    report.resolved = {
        "description": profile.description,
        "pythonCommand": python_command(),
        "target": str(target) if target is not None else None,
        "repoRoot": str(repo_root) if repo_root is not None else None,
        "repoKind": repo_kind,
        "scope": scope,
        "scanRoot": str(scans / repo_name),
        "stateDir": str(state),
        "workerSlots": args.worker_slots,
    }

    json.dump(report.to_json(), sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
