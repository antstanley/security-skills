# Scan Artifact Paths

Use these shared path conventions for Security scan workflows unless the user explicitly provides different input or output paths.

## Base Paths

- `skill_root=<skill_root>`
- `repo_root=<repoRoot reported by the preflight helper>`: the repository root directory. Preflight also reports `scope`, the requested scan path relative to `repo_root`.
- `repo_name=<basename of repo_root>`: the final path component of `repo_root`, never the basename of a scoped sub-path.
- `target_id=<targetId from the target-identity helper below>`
- `system_temp_dir=<platform temporary directory>`
- `security_scans_dir=<system_temp_dir>/security-scans/<repo_name>`: the same directory preflight reports as `scanRoot`.
- `scan_id=<revision_label>_<scan timestamp>`, where `revision_label` comes from the target-identity helper output:
  - Git targets (`git_revision`, `git_worktree`, `git_diff`): the `revision` commit id.
  - `directory_snapshot` targets, which have no `revision`: `snapshot-` followed by the first 12 hex characters after the final `:` of `snapshotDigest` (for example `snapshot-ed88f96a4c1a` for `security-snapshot/v1:sha256:ed88f96a4c1a…`).
- `scan_dir=<security_scans_dir>/<scan_id>`
- `artifacts_dir=<scan_dir>/artifacts`
- `context_dir=<artifacts_dir>/01_context`
- `discovery_dir=<artifacts_dir>/02_discovery`
- `coverage_dir=<artifacts_dir>/03_coverage`
- `reconciliation_dir=<artifacts_dir>/04_reconciliation`
- `findings_dir=<artifacts_dir>/05_findings`

The preflight helper reports the resolved `scanRoot`; prefer it over re-deriving the path. `SECURITY_SCAN_ROOT` overrides it. Otherwise use the active process temporary directory (for example, `%TEMP%` on Windows or `$TMPDIR` when configured on Unix-like hosts) instead of hardcoding `/tmp`.

Resolve `<python_command>` to the configured Python interpreter (`$PYTHON` when one is provided), otherwise use `python` on Windows and `python3` on Unix-like hosts.

## Target Identity And Snapshot Digest

Resolve the drafted manifest's `scan.target` block by running the extracted helper; never hand-compute `targetId` or `snapshotDigest`:

```text
<python_command> <skill_root>/scripts/target_identity.py --target <target_dir> [--kind git_worktree|git_revision|directory_snapshot]
<python_command> <skill_root>/scripts/target_identity.py --target <repo_root> --kind git_diff --base <base> [--head <head> | --mode local-patch]
```

The helper prints a JSON object with `kind`, `targetId`, `snapshotDigest`, `revision` for Git targets, and supporting `git` metadata. Omit `--kind` to let it classify the target (`git_revision` for a clean checkout, `git_worktree` for a dirty one, `directory_snapshot` outside Git); pass `--kind git_diff --base <base>` with `--head <head>` for committed ranges or `--mode local-patch` for working-tree changes; the helper then also prints `baseRevision` and, for ranges, `headRevision`. Copy `kind`, `targetId`, `snapshotDigest`, `revision`, `baseRevision`, and `headRevision` when present into the drafted `scan.target`, then set `displayName` yourself. Record `remote` only as a sanitized URL without credentials, query, or fragment. Run the helper at manifest-authoring time so the digest reflects the reviewed content; the finalizer validates these values at seal time but does not compute them. The identity and digest scheme is defined in `<skill_root>/references/scan-contract.md`.

## Threat Model (Phase 1) Paths

- Resolved SECURITY.md guidance: `<context_dir>/security_guidance.md`
- Repository-scoped threat model: `<security_scans_dir>/threat_model.md`
- Per-scan threat model copy: `<context_dir>/threat_model.md`
- Later scan phases should treat `<context_dir>/threat_model.md` as the source of truth.
- When a repository-scoped threat model already exists, copy it to `<context_dir>/threat_model.md` without alteration for auditability.

End each repository-scoped threat model with these two lines:

- `Repository: <target_id>`
- `Version: <revision for an immutable Git tree; snapshot digest otherwise>`

## Finding Discovery (Phase 2) Paths

### Standard Repository Or Scoped-Path Scan

- Deterministic in-scope file list: `<discovery_dir>/in_scope_files.txt`
- Compact combined candidate ledger: `<discovery_dir>/candidate_ledger.jsonl`
  - The combiner reads one or more temporary raw candidate sources, validates them against the in-scope file list, and merges rows that describe the same bug: a primary location (`root_control` or `sink`, or every location when a row has neither) in the same file with an overlapping line range, CWE sets that share an id or are both empty, and no conflicting explicit `instance` labels. Merged rows take the union of CWE ids and locations, keep every text, list contributing input rows in `sources`, and keep the `candidate_id` of their first row, so `candidate_id` values stay deterministic. Pass `--rejects <path>` to skip and record invalid rows instead of failing the whole merge. This is the sole durable standard candidate artifact.
  - After normalization, compact validation adds exactly one `validation` object to every row with `disposition` (`reportable`, `suppressed`, `not_applicable`, or `deferred`), `method`, `confidence` (`high`, `medium`, or `low`, from the confidence scale in `static-finding-assessment.md`), `confidence_rationale`, concise `rubric` and `evidence`, `counterevidence_or_proof_gap`, `remaining_uncertainty`, and optional `artifact_paths`. Add `source`, `control`, `sink`, or `preconditions` only when they clarify or differ from the discovery fields.
  - When validation expands a broad family row into independently triggerable children, the row's `validation` object also carries `children`: an array with one entry per child. Each entry has:
    - `child_id`: `<candidate_id>.<child-slug>`, where the child slug is a short lowercase semantic label using only `a-z`, `0-9`, and `-` (for example `executemany` or `yaml-load-all`). Keep it unique within the row, free of line numbers, and stable across reruns.
    - `locations`: the child's own root-control, sink, concrete-implementation, or protected-action lines, plus any shared entrypoint or wrapper lines in its proof tuple, in the discovery location shape (repository-relative `path`, positive `start_line`, optional `end_line`, `role`).
    - `disposition`, `confidence`, `confidence_rationale`, `evidence`, and `counterevidence_or_proof_gap` for that child alone.
    - optional `source`, `control`, `sink`, `preconditions`, or `artifact_paths` when they differ from the parent record.

    The parent record keeps the shared family evidence, such as a representative PoC, and its `disposition` summarizes the children: `reportable` if any child is reportable, otherwise `deferred` if any child is deferred, otherwise `not_applicable` if every child is not applicable, otherwise `suppressed`. Children exist only inside the nested record; they never add, split, or edit ledger rows or discovery fields.
  - Compact attack-path analysis adds exactly one `attack_path` object to each validation row marked `reportable` or `deferred`, with `decision` (`reportable`, `ignore`, or `deferred`), `dataflow`, `reachability`, `counterevidence`, `impact` and `likelihood` (`high`, `medium`, `low`, `ignore`, or `unknown`), `severity` (`critical`, `high`, `medium`, `low`, `ignore`, or `unknown`), `severity_rationale`, `change_conditions`, and `proof_gap` when deferred. A `reportable` decision requires severity `critical`, `high`, `medium`, or `low`; `ignore` requires severity `ignore`; `deferred` uses a provisional reportable severity or `unknown`.
  - When the row's `validation` has `children`, `attack_path` also carries `children`: one entry for every validation child whose disposition is `reportable` or `deferred`, each with the matching `child_id` and the full set of `attack_path` fields above for that child alone. The parent `decision` summarizes the children (`reportable` if any child is reportable, otherwise `deferred` if any is deferred, otherwise `ignore`), and the parent `severity` is the highest severity among the children with that decision (`unknown` only when every such child is `unknown`). Final-report assembly reads the child entries, not the parent summary.
  - Preserve all discovery fields and row order during enrichment, rewrite atomically, and do not pass the enriched ledger back to `normalize_candidates.py`.
- Optional compact validation evidence: `<discovery_dir>/validation_artifacts/<candidate_id>/`
  - Create this directory only for actual PoCs, crafted inputs, or logs and reference those paths from the row's `validation` object. Do not create placeholder per-candidate directories or narrative reports.

The raw/deduped candidate, per-finding receipt, and phase-report paths below are for diff and resumed legacy workflows. Compact standard scans and the deep-scan centralized tail use the enriched ledger instead.

### Deep Scan Discovery

- Deep discovery root: `<discovery_dir>/deep`
- Per-pass threat model: `<discovery_dir>/deep/pass-NNN/threat_model.md`
- Per-pass raw candidates: `<discovery_dir>/deep/pass-NNN/raw_candidates.jsonl`
- Discovery manifest: `<discovery_dir>/deep/discovery_manifest.json`

### Coverage Planning

- Advisory seed research: `<context_dir>/seed_research.md`
- Diff worklist input: `<discovery_dir>/rank_input.jsonl` if applicable
- Diff deep-review input: `<discovery_dir>/deep_review_input.jsonl` if applicable
- Finding discovery report: `<discovery_dir>/finding_discovery_report.md`

### Deep Review

- Scoped work ledger: `<discovery_dir>/work_ledger.jsonl` if applicable
- Scoped raw candidates: `<discovery_dir>/raw_candidates.jsonl` if applicable

### Candidate Reconciliation

- Candidate findings directory: `<findings_dir>/`
- Per-finding directory: `<findings_dir>/<candidate_id>/`
- Per-finding candidate ledger: `<findings_dir>/<candidate_id>/candidate_ledger.jsonl`
- Scoped dedupe report: `<reconciliation_dir>/dedupe_report.md` if applicable
- Scoped deduped candidates: `<reconciliation_dir>/deduped_candidates.jsonl` if applicable

### Coverage

- Repository-wide coverage ledger: `<coverage_dir>/repository_coverage_ledger.md`
  - This is a coverage artifact, not a findings list: it should include checked surfaces with not_applicable, suppressed, deferred, or reportable dispositions.
- Reviewed surfaces summary: `<coverage_dir>/reviewed_surfaces.md` if applicable

## Validation (Phase 3) Paths

Compact standard scans use the nested `validation` record and optional compact evidence path above. Other scan modes use these paths:

- Scan-level validation summary: `<findings_dir>/validation_summary.md` if applicable
- Per-finding validation report: `<findings_dir>/<candidate_id>/validation_report.md`
- Per-finding validation artifacts: `<findings_dir>/<candidate_id>/validation_artifacts/`

## Attack-Path Analysis (Phase 4) Paths

Compact standard scans use the nested `attack_path` record above. Other scan modes use these paths:

- Scan-level attack-path analysis report: `<findings_dir>/attack_path_analysis_report.md` if applicable
- Per-finding attack-path analysis report: `<findings_dir>/<candidate_id>/attack_path_analysis_report.md`

## Final Report Paths

- Final scan report: `<scan_dir>/report.md`
- Detailed vulnerability write-up: `<scan_dir>/findings/<slug>/<slug>.md`
- Per-finding PoC and supporting files: `<scan_dir>/findings/<slug>/poc/...`
- Structural hardening portfolio: `<scan_dir>/hardening/hardening.md`
- Hardening analysis, proposals, and diagrams: `<scan_dir>/hardening/...`
- Final report validation notes, when validation fails: `<scan_dir>/report_validation.md`

## Fix Finding Paths

- Fix report, when using an existing scan artifact directory: `<artifacts_dir>/fix_report.md`

## Placement Rules

- Put scan phase outputs and supporting evidence under the numbered artifact subdirectories above.
- Keep fix-finding outputs outside the numbered scan phases because fix-finding can run standalone or against an existing scan.
- Do not author the final `report.md` directly. Put complete scan-level report semantics in the canonical JSON files. Detailed per-finding prose in `findings/<slug>/<slug>.md` and derived design guidance under `hardening/` are optional for a standard scan. Finalization deterministically writes the unsealed `report.md` projection and links any recorded write-ups and hardening portfolio. Do not add these derived documents to the sealed artifact list.
- Keep the full scan bundle together under `scan_dir`.
