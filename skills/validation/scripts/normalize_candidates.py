#!/usr/bin/env python3
"""Validate and combine security-scan candidates into deterministic JSONL.

Rows describe the same candidate when they are compatible: a primary location
(`root_control` or `sink`, or every location when a row has neither) shares a
path and an overlapping line range, the CWE sets intersect or are both empty,
and the rows do not carry different explicit `instance` labels. Rows are read
in sorted input-path then line order; each joins the first earlier group whose
every member it is compatible with, or starts a new group. Earlier groups are
therefore never split or renumbered by later inputs, and a group's
`candidate_id` comes from its first row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

CWE = re.compile(r"(?i)CWE-(\d+)")
ROLES = {
    "entrypoint": 0,
    "entrypoint/wrapper": 1,
    "source": 2,
    "root_control": 3,
    "sink": 4,
    "concrete_implementation": 5,
    "evidence": 6,
}
PRIMARY_ROLES = {"root_control", "sink"}
FIELDS = {
    "candidate_id",
    "cwe_ids",
    "locations",
    "summary",
    "evidence",
    "context",
    "instance",
}


def text_field(row: dict[str, Any], field: str, *, required: bool = True) -> str | None:
    value = row.get(field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: expected a non-empty string")
    return value.strip()


def cwe_ids(row: dict[str, Any]) -> list[str]:
    value = row.get("cwe_ids")
    if not isinstance(value, list):
        raise ValueError("cwe_ids: expected an array")
    found: set[int] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError("cwe_ids: expected CWE strings")
        match = CWE.fullmatch(item.strip())
        if match is None or int(match[1]) < 1:
            raise ValueError(f"cwe_ids: unsupported value {item!r}")
        found.add(int(match[1]))
    return [f"CWE-{number}" for number in sorted(found)]


def relative_file(value: Any, repo_root: Path) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("path: expected a non-empty repository-relative path")
    raw = value
    if sys.platform == "win32":
        raw = raw.replace("\\", "/")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or ".." in path.parts
        or (sys.platform == "win32" and re.match(r"^[A-Za-z]:", raw))
    ):
        raise ValueError("path: expected a repository-relative path without traversal")
    resolved = (repo_root / raw).resolve(strict=True)
    try:
        relative = resolved.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise ValueError("path: must resolve inside --repo-root") from error
    if not resolved.is_file():
        raise ValueError("path: expected a regular file")
    return relative, resolved


def positive_line(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{field}: expected a positive integer")
    return value


def normalize_locations(
    row: dict[str, Any], repo_root: Path, line_counts: dict[Path, int]
) -> list[dict[str, Any]]:
    value = row.get("locations")
    if not isinstance(value, list) or not value:
        raise ValueError("locations: expected a non-empty array")
    normalized: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("locations: expected location objects")
        unknown = set(item) - {"path", "start_line", "end_line", "role"}
        if unknown:
            raise ValueError(f"locations: unsupported fields {', '.join(sorted(unknown))}")
        relative, source = relative_file(item.get("path"), repo_root)
        if (
            not relative.strip()
            or "\\" in relative
            or any(":" in part for part in PurePosixPath(relative).parts)
        ):
            raise ValueError("path: expected a safe repository-relative POSIX path")
        start = positive_line(item.get("start_line"), "start_line")
        end = positive_line(item.get("end_line", start), "end_line")
        if end < start:
            raise ValueError("end_line: must be greater than or equal to start_line")
        if source not in line_counts:
            line_counts[source] = len(source.read_bytes().splitlines())
        if end > line_counts[source]:
            raise ValueError(f"line range {start}-{end} exceeds {relative}:{line_counts[source]}")
        role = item.get("role")
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError(f"role: unsupported value {role!r}")
        key = (relative, start, end, role)
        normalized[key] = {
            "path": relative,
            "start_line": start,
            "end_line": end,
            "role": role,
        }
    return sorted(
        normalized.values(),
        key=lambda item: (
            ROLES[item["role"]],
            item["path"],
            item["start_line"],
            item["end_line"],
        ),
    )


def read_scope(path: Path, repo_root: Path) -> set[str]:
    contents = path.read_bytes().decode("utf-8")
    lines = contents.split("\n")
    listed_rows = set(lines)

    def is_scope_file(value: str) -> bool:
        try:
            relative_file(value, repo_root)
        except (OSError, ValueError):
            return False
        return True

    carriage_rows = {
        line: (is_scope_file(line), is_scope_file(line.removesuffix("\r")))
        for line in lines
        if line.endswith("\r") and line != "\r" and sys.platform != "win32"
    }
    crlf_evidence = any(line == "\r" for line in lines) or any(
        stripped and not literal for literal, stripped in carriage_rows.values()
    )
    literal_evidence = any(literal and not stripped for literal, stripped in carriage_rows.values())

    scope: set[str] = set()
    for number, line in enumerate(lines, 1):
        if sys.platform == "win32" or line == "\r":
            line = line.removesuffix("\r")
        elif line.endswith("\r"):
            literal, stripped = carriage_rows[line]
            if stripped and not literal:
                line = line.removesuffix("\r")
            elif stripped and literal:
                if number == len(lines) and not contents.endswith("\n"):
                    pass
                elif line.removesuffix("\r") in listed_rows:
                    pass
                elif crlf_evidence and not literal_evidence:
                    line = line.removesuffix("\r")
                elif literal_evidence and not crlf_evidence:
                    pass
                else:
                    raise ValueError(f"in-scope file row {number}: ambiguous carriage-return paths")
            elif not literal and crlf_evidence:
                line = line.removesuffix("\r")
        if not line:
            continue
        try:
            relative, _ = relative_file(line, repo_root)
        except (OSError, ValueError) as error:
            raise ValueError(f"in-scope file row {number}: {error}") from error
        scope.add(relative)
    return scope


def normalize_candidate(
    row: dict[str, Any], repo_root: Path, scope: set[str], line_counts: dict[Path, int]
) -> dict[str, Any]:
    unknown = set(row) - FIELDS
    if unknown:
        raise ValueError(f"unsupported fields {', '.join(sorted(unknown))}")
    if "candidate_id" in row:
        text_field(row, "candidate_id")
    candidate_locations = normalize_locations(row, repo_root, line_counts)
    if not any(item["path"] in scope for item in candidate_locations):
        raise ValueError("locations: expected at least one in-scope file")
    result: dict[str, Any] = {
        "cwe_ids": cwe_ids(row),
        "locations": candidate_locations,
        "summary": text_field(row, "summary"),
        "evidence": text_field(row, "evidence"),
    }
    context = text_field(row, "context", required=False)
    if context is not None:
        result["context"] = context
    instance = text_field(row, "instance", required=False)
    if instance is not None:
        result["instance"] = instance
    return result


def identity(row: dict[str, Any]) -> str:
    return json.dumps(
        {
            "cwe_ids": row["cwe_ids"],
            "locations": row["locations"],
            "instance": row.get("instance"),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def primary_locations(row: dict[str, Any]) -> list[dict[str, Any]]:
    primary = [item for item in row["locations"] if item["role"] in PRIMARY_ROLES]
    return primary or row["locations"]


def instance_label(row: dict[str, Any]) -> str | None:
    instance = row.get("instance")
    return " ".join(instance.split()).casefold() if isinstance(instance, str) else None


def compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_instance, right_instance = instance_label(left), instance_label(right)
    if left_instance and right_instance and left_instance != right_instance:
        return False
    left_cwes, right_cwes = set(left["cwe_ids"]), set(right["cwe_ids"])
    if (left_cwes or right_cwes) and not left_cwes & right_cwes:
        return False
    return any(
        first["path"] == second["path"]
        and first["start_line"] <= second["end_line"]
        and second["start_line"] <= first["end_line"]
        for first in primary_locations(left)
        for second in primary_locations(right)
    )


def merged_text(group: list[dict[str, Any]], field: str) -> str:
    return "\n".join(sorted({item[field] for item in group if field in item}))


def merged_locations(group: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {
        (item["path"], item["start_line"], item["end_line"], item["role"]): item
        for row in group
        for item in row["locations"]
    }
    return sorted(
        unique.values(),
        key=lambda item: (
            ROLES[item["role"]],
            item["path"],
            item["start_line"],
            item["end_line"],
        ),
    )


def merged_cwe_ids(group: list[dict[str, Any]]) -> list[str]:
    numbers = {int(cwe.removeprefix("CWE-")) for row in group for cwe in row["cwe_ids"]}
    return [f"CWE-{number}" for number in sorted(numbers)]


def combine(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group compatible rows; `rows` must already be in sorted source order."""

    groups: list[list[dict[str, Any]]] = []
    for row in rows:
        for group in groups:
            # Complete linkage: a row joins only when it matches every member,
            # so one broad row cannot chain two distinct sibling bugs together.
            if all(compatible(row, member) for member in group):
                group.append(row)
                break
        else:
            groups.append([row])

    combined: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for group in groups:
        candidate_id = f"candidate-{hashlib.sha256(identity(group[0]).encode()).hexdigest()[:16]}"
        if candidate_id in seen_ids:
            fallback = json.dumps([identity(row) for row in group], ensure_ascii=False)
            candidate_id = f"candidate-{hashlib.sha256(fallback.encode()).hexdigest()[:16]}"
        seen_ids.add(candidate_id)
        result: dict[str, Any] = {
            "candidate_id": candidate_id,
            "cwe_ids": merged_cwe_ids(group),
            "locations": merged_locations(group),
            "summary": merged_text(group, "summary"),
            "evidence": merged_text(group, "evidence"),
            "sources": [row["_source"] for row in group],
        }
        context = merged_text(group, "context")
        if context:
            result["context"] = context
        instance = next((row["instance"] for row in group if "instance" in row), None)
        if instance is not None:
            result["instance"] = instance
        combined.append(result)
    combined.sort(
        key=lambda row: (
            primary_locations(row)[0]["path"],
            primary_locations(row)[0]["start_line"],
            row["candidate_id"],
        )
    )
    return combined


def source_label(source: Path, output: Path) -> str:
    try:
        return source.relative_to(output.parent).as_posix()
    except ValueError:
        return source.as_posix()


def write_jsonl_atomically(output: Path, rows: list[dict[str, Any]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        for row in rows
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--input", nargs="+", required=True, help="Candidate JSONL inputs.")
    parser.add_argument("--out", required=True, help="Combined candidate JSONL output.")
    parser.add_argument("--repo-root", required=True, help="Repository root for candidate paths.")
    parser.add_argument("--in-scope-files", required=True, help="Repository-relative file list.")
    parser.add_argument(
        "--rejects",
        help=(
            "Skip invalid rows instead of failing: write each rejected row's input, line, "
            "and reason to this JSONL path and still write the valid rows to --out."
        ),
    )
    args = parser.parse_args()
    try:
        repo_root = Path(args.repo_root).expanduser().resolve(strict=True)
        if not repo_root.is_dir():
            raise ValueError("--repo-root: expected a directory")
        output = Path(args.out).expanduser().resolve(strict=False)
        scope_path = Path(args.in_scope_files).expanduser().resolve(strict=True)
        inputs = sorted({Path(value).expanduser().resolve(strict=True) for value in args.input})
        rejects_path = (
            Path(args.rejects).expanduser().resolve(strict=False) if args.rejects else None
        )
        if output in inputs:
            raise ValueError("--out: must not also be an input")
        if output == scope_path:
            raise ValueError("--out: must not replace --in-scope-files")
        if rejects_path is not None and rejects_path in {output, scope_path, *inputs}:
            raise ValueError("--rejects: must differ from --out, --in-scope-files, and inputs")
        scope = read_scope(scope_path, repo_root)
        line_counts: dict[Path, int] = {}
        rows: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for source in inputs:
            label = source_label(source, output)
            # Decode per line so one undecodable row is rejected on its own.
            for number, raw in enumerate(source.read_bytes().split(b"\n"), 1):
                try:
                    line = raw.decode("utf-8")
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("expected a JSON object")
                    normalized = normalize_candidate(row, repo_root, scope, line_counts)
                except (ValueError, TypeError, OSError, RecursionError) as error:
                    if rejects_path is None:
                        raise ValueError(f"{source} row {number}: {error}") from error
                    rejected.append({"input": label, "line": number, "reason": str(error)})
                    continue
                normalized["_source"] = f"{label}:{number}"
                rows.append(normalized)
        combined = combine(rows)
        write_jsonl_atomically(output, combined)
        summary = f"Combined {len(rows)} candidate rows into {len(combined)} rows in {output}"
        if rejects_path is not None:
            write_jsonl_atomically(rejects_path, rejected)
            summary += f"; rejected {len(rejected)} invalid rows (see {rejects_path})"
        print(summary)
    except (OSError, ValueError) as error:
        print(f"normalize_candidates: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
