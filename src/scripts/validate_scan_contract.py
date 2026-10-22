#!/usr/bin/env python3
"""Validate a sealed security scan contract without mutating it."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_sibling(file_name: str, module_name: str) -> ModuleType:
    script = Path(__file__).resolve().with_name(file_name)
    spec = importlib.util.spec_from_file_location(module_name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scan contract helper: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = _load_sibling("finalize_scan_contract.py", "security_scan_contract")
REPORT_FORMAT = _load_sibling("validate_report_format.py", "security_report_format")


def _read_report_bytes(scan_dir: Path, limit: int) -> bytes:
    descriptor = FINALIZER.open_scan_local_file_descriptor(scan_dir, "report.md", "report.md")
    with open(descriptor, "rb", closefd=True) as handle:
        return handle.read(limit)


def _validate_report_projection(
    scan_dir: Path,
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> None:
    """Require report.md to be the exact projection finalization would write."""

    expected = FINALIZER._generate_report_projection(manifest, findings, coverage)
    actual = _read_report_bytes(scan_dir, len(expected) + 1)
    try:
        text = actual.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FINALIZER.ContractError("report.md: expected UTF-8 text") from exc
    errors = REPORT_FORMAT.validate_report(text)
    if errors:
        raise FINALIZER.ContractError("report.md: invalid report format: " + "; ".join(errors))
    if actual != expected:
        raise FINALIZER.ContractError(
            "report.md: does not match the projection generated from the sealed canonical "
            "JSON; rerun finalize_scan_contract.py to regenerate it"
        )


def validate_contract(scan_dir: Path) -> dict[str, Any]:
    """Return validated canonical documents for one sealed scan."""

    scan_dir = FINALIZER._require_scan_directory(scan_dir.expanduser().resolve(strict=True))
    schema_dir = Path(__file__).resolve().parents[1] / "schemas"
    manifest, _ = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        "scan-manifest.json",
        "scan-manifest.json",
    )
    FINALIZER._validate_manifest(manifest)
    FINALIZER.validate_against_schema(manifest, schema_dir / "scan-manifest.schema.json")

    scan = FINALIZER._require_dict(manifest, "scan", "manifest")
    findings_ref = scan["findingsRef"]
    coverage_ref = scan["coverageRef"]
    findings, findings_bytes = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        findings_ref,
        findings_ref,
    )
    coverage, coverage_bytes = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        coverage_ref,
        coverage_ref,
    )
    FINALIZER._validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            findings_ref: findings_bytes,
            coverage_ref: coverage_bytes,
        },
    )
    FINALIZER._validate_findings(manifest, findings)
    FINALIZER._validate_derived_finding_identities(manifest, findings)
    FINALIZER._validate_coverage(manifest, coverage, scan_dir)
    FINALIZER._validate_coverage_findings_consistency(findings, coverage)
    FINALIZER._validate_sealed_coverage_receipts(scan, coverage)
    FINALIZER._require_derived_writeup_files(scan_dir, findings)
    FINALIZER._require_hardening_portfolio_file(scan_dir, scan)
    FINALIZER.validate_against_schema(findings, schema_dir / "findings.schema.json")
    FINALIZER.validate_against_schema(coverage, schema_dir / "coverage.schema.json")
    _validate_report_projection(scan_dir, manifest, findings, coverage)
    return {
        "scanDir": str(scan_dir),
        "manifest": manifest,
        "findings": findings,
        "coverage": coverage,
    }


def receipt(validated: dict[str, Any]) -> dict[str, Any]:
    scan_dir = Path(validated["scanDir"])
    scan = validated["manifest"]["scan"]
    return {
        "status": "valid",
        "scanDir": str(scan_dir),
        "manifestPath": str(scan_dir / "scan-manifest.json"),
        "findingsPath": str(scan_dir / scan["findingsRef"]),
        "coveragePath": str(scan_dir / scan["coverageRef"]),
        "reportPath": str(scan_dir / "report.md"),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        validated = validate_contract(args.scan_dir)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"scan contract validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt(validated), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
