#!/usr/bin/env python3
"""Validate a sealed scan and list or select findings for tracking."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_scan_contract_validator() -> ModuleType:
    script = Path(__file__).resolve().with_name("validate_scan_contract.py")
    spec = importlib.util.spec_from_file_location("security_scan_validator", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scan contract validator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAN_CONTRACT = _load_scan_contract_validator()
FINALIZER = SCAN_CONTRACT.FINALIZER
validate_contract = SCAN_CONTRACT.validate_contract


# Linear, Jira, and GitHub issue batches never exceed this many findings.
MAX_BATCH = 25


def _as_list(selector: str | Sequence[str] | None) -> list[str]:
    if selector is None:
        return []
    if isinstance(selector, str):
        return [selector]
    return list(selector)


def _select_findings(
    findings: list[dict[str, Any]],
    finding_ids: list[str],
    fingerprints: list[str],
) -> list[dict[str, Any]]:
    if finding_ids:
        key, flag, values = "findingId", "--finding-id", finding_ids
    elif fingerprints:
        key, flag, values = "primary fingerprint", "--fingerprint", fingerprints
    else:
        return findings

    if len(values) > MAX_BATCH:
        raise ValueError(f"a batch may select at most {MAX_BATCH} findings; got {len(values)}")
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ValueError(f"{flag} repeats a value: {', '.join(duplicates)}")

    selected: list[dict[str, Any]] = []
    for value in values:
        if key == "findingId":
            matches = [finding for finding in findings if finding["findingId"] == value]
        else:
            matches = [
                finding for finding in findings if finding["fingerprints"]["primary"] == value
            ]
        if len(matches) != 1:
            raise ValueError(f"{flag} {value} did not resolve exactly one finding")
        selected.append(matches[0])

    resolved = [finding["findingId"] for finding in selected]
    if len(set(resolved)) != len(resolved):
        raise ValueError("two selectors resolved to the same finding")
    return selected


def validate_source(
    scan_dir: Path,
    *,
    finding_id: str | Sequence[str] | None = None,
    fingerprint: str | Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Validate the sealed scan and return the selected findings in request order.

    Each selector may be one value or a batch of up to MAX_BATCH distinct values.
    Without a selector, every finding in the scan is returned.
    """
    finding_ids = _as_list(finding_id)
    fingerprints = _as_list(fingerprint)
    if finding_ids and fingerprints:
        raise ValueError("use only one of --finding-id or --fingerprint")

    validated = validate_contract(scan_dir)
    findings_document = validated["findings"]
    return _select_findings(findings_document["findings"], finding_ids, fingerprints)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path)
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument(
        "--finding-id",
        action="append",
        help=f"select a finding by id; repeat for a batch of up to {MAX_BATCH}",
    )
    selector.add_argument(
        "--fingerprint",
        action="append",
        help=f"select a finding by primary fingerprint; repeat for a batch of up to {MAX_BATCH}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        findings = validate_source(
            args.scan_dir,
            finding_id=args.finding_id,
            fingerprint=args.fingerprint,
        )
    except (OSError, ValueError, RecursionError) as exc:
        print(f"tracking source preflight failed: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding["findingId"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
