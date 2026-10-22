---
name: finding-discovery
description: Use when a security scan is already in its finding-discovery phase or the user explicitly asks to discover candidate security findings in a repository or code change. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Finding Discovery

## Runtime portability

Read [runtime guidance](../../references/runtime.md) before invoking helpers or
companion skills. Resolve `<skill_root>` from this installed skill's location,
not the repository being reviewed. Use the host's available tools and preserve
the workflow's approval and independent-review requirements.


## Objective

Investigate the proposed code or code changes for technically plausible security vulnerabilities using the threat model as context.

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

## SECURITY.md Guidance Gate

Read `../../references/security-guidance.md` and resolve the applicable policy before inspecting each source file. A delegated file-review worker must do the same before reading its assigned source.

### Code Diff Workflow
If the scan target is for a targeted code-diff:

- Read `../security-scan/references/scan-artifacts-and-ledger.md`.
- Generate `rank_input.jsonl` deterministically from changed source-like files with `<python_command> <skill_root>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode revisions --head <head> --out <discovery_dir>/rank_input.jsonl` for PR, commit, and branch diffs, or `<python_command> <skill_root>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode local-patch --out <discovery_dir>/rank_input.jsonl` for a local patch.
  `--repo` may be the repository root or any directory inside it; rows always use repository-root-relative paths. A local patch covers staged, unstaged, and untracked files that Git does not ignore. The helper keeps every changed text file, including CI workflows, tests, build files, Dockerfiles, infrastructure code, templates, extensionless scripts, deleted files (with an empty preview), and changed symlinks (with an empty preview, never followed). It skips only binary files, dependency lockfiles (such as `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `uv.lock`, `go.sum`, and `Gemfile.lock`), and minified bundles or source maps (`*.min.js`, `*.min.css`, `*.map`), and prints every skipped path. Review a skipped lockfile directly when the change set's security behavior depends on it, such as a changed dependency source.
- Copy every diff row into `deep_review_input.jsonl` with `<python_command> <skill_root>/scripts/generate_rank_input.py copy-deep-review-input --rank-input <discovery_dir>/rank_input.jsonl --out <discovery_dir>/deep_review_input.jsonl`. Diff scans do not rank or drop changed files before deep review.
- Add directly supporting files required to understand the changed security behavior only when repository evidence shows they are needed. Do not use them to broaden into unrelated repository-wide enumeration.
- Deep-review every file in `deep_review_input.jsonl` using the shared scoped file-review rules.
- Stay anchored to the changed code and directly supporting files. Unchanged siblings are context or negative controls unless the diff newly reaches them, weakens their shared control, or changes a shared sink/helper they depend on.
- When the diff is too large to review credibly as one parent-agent pass, use file-review subagents when they are available under the resolved scan authorization and follow the shared scoped deep-review rules in `../security-scan/references/scan-artifacts-and-ledger.md#scoped-deep-review`.

### Exhaustive Repository Or Scoped-Path Workflow

If the scan target is repository-wide or a scoped path — and this is not a deep-scan discovery pass — use only the concise detection-first procedure in `../security-scan/references/repository-wide-scan.md`. It replaces the checklist, phase-specific output, and receipt requirements below for standard scans; do not load additional repository-wide ranking, ledger, validation, or attack-path references. The remaining guidance in this skill continues to apply to diff-scoped discovery.

### Deep-Pass Discovery Mode

When `deep-security-scan` (or another invoking workflow) explicitly runs this skill as one independent discovery pass, the invoker supplies a pass-local raw-candidate output path such as `<deep_dir>/pass-NNN/raw_candidates.jsonl`. In that mode:

- review the full resolved scope with the same detection standards and the raw candidate row shape from `../security-scan/references/repository-wide-scan.md`
- write raw candidate rows only to the caller-specified pass-local path
- do not run `normalize_candidates.py`, and do not write or modify the shared `<discovery_dir>/candidate_ledger.jsonl` — the deep-scan coordinator owns merging
- do not run validation, attack-path analysis, or any other tail phase; the pass produces candidates only

## Discovery Checklist

Use this checklist to keep discovery specific without turning it into validation or attack-path analysis:

- Use tools to inspect the changed files and the minimum supporting files they rely on before deciding anything.
- Treat the commit message and title as potentially incomplete or misleading; trust the actual code path more than the narrative.
- Follow the entire changed-code chain far enough to understand how the diff affects authorization, trust boundaries, dangerous sinks, or security controls.
- Prefer multiple distinct finding families only when they come from different root causes; do not split one issue into cosmetic variants, but keep independently reachable instances as separate candidate entries.
- When the diff changes a shared helper, guard, route pattern, template pattern, or sink wrapper, expand to sibling call sites that the changed code directly affects, and keep each vulnerable instance addressable.
- Look for attacker-controlled input, broken enforcement, or dangerous sinks introduced or made reachable by the change.
- Stay anchored to the diff and the supporting files it depends on rather than drifting into unrelated repository scanning.
- For advisory-seeded repository-wide and scoped-path scans, keep any supplied advisory row id, exact file, line, source, sink, or broken-control hint visible in the candidate ledger. A neighboring same-CWE finding can be an additional candidate, but it does not satisfy the seeded row unless it covers the same vulnerable control and effect.
- Do not group many vulnerable files under one candidate when the files have separate line-level source/sink/control evidence.
- When a dangerous sink has multiple call sites, enumerate each call site with its own source and closest control.
- When repeated templates, query builders, parser operations, auth/object endpoints, or shared-helper callers are independently reachable, keep each vulnerable file and sink/control line as its own candidate instance even if the final report later groups related prose.
- When source/sink evidence crosses a wrapper into a shared sink/control helper, include both locations in the candidate so validation can test reachability without losing the root vulnerable line.
- For diff-scoped scans, include `relevant_lines` only when the bug overlaps the diff and those lines are genuinely relevant to the issue.
- Include CWE IDs when known; use an empty list when the class is unclear.

### Family-Specific Rules

Read `references/discovery-deep-dive.md` and apply every rule whose family appears in the code under review. It carries the mandatory long-tail checklist for instance enumeration and family expansion, advisory-seeded rows, deserialization/parser/file-format object models, structured patch and operation families, duplicated controls and cross-boundary framework inputs, query APIs, SSRF and command runners, resource-serving/filesystem/archive families, auth/SSO/SAML/protocol state, and self-service updates and templates. Those rules are part of this checklist, relocated for length, not optional extras.

## Finding Bar

Prefer technically plausible candidates such as:

- authz bypass
- confused deputy
- SSRF
- path traversal
- injection with a real sink
- cross-tenant data exposure
- sensitive state change without correct enforcement
- sandbox or trust-boundary escape

Discovery identifies plausible candidates and preserves their evidence; it does not own final severity calibration. For reportability and severity examples, defer to `../attack-path-analysis/references/severity-policy.md` during attack-path analysis.

Avoid:

- generic "needs more validation" comments with no exploit path
- maintainability complaints
- duplicate variants of the same root issue

## Output Contract

If there are no plausible candidates, return a no-findings result.

For repository-wide and scoped-path scans, and for deep-pass discovery, write each candidate as one raw candidate row using only the fields in `../security-scan/references/repository-wide-scan.md`: `cwe_ids`, `locations`, `summary`, `evidence`, and optional `context` and `instance`. The normalizer rejects a row with any other field, such as `title`, and assigns `candidate_id` itself. Put the one-line title at the start of `summary`; put the attacker-controlled source, sink or broken control, impact, closest control, and why the issue is plausible in `evidence`; and put any seed, ledger row, or advisory reference in `context`. Set `instance` only to tell apart separate bugs that share the same locations, such as different request parameters or operations on one line. Do not use it as a general `<family>:<file>:<line>` key: the file and line already live in `locations`, and two rows with different `instance` labels are never merged.

For diff-scoped discovery, for each candidate include:

- candidate id
- title
- affected locations, with labels when more than one applies: `entrypoint/wrapper`, `root_control`, `sink`, and `concrete_implementation`
- instance label when separate bugs share the same locations
- seed or ledger row id for seeded/root-control rows when available
- advisory/source reference for advisory-seeded rows when available
- attacker-controlled source
- vulnerable sink or broken control
- impact
- why the issue is plausible from the current code
- closest apparent control and why it is absent, bypassed, mis-scoped, or incomplete
- whether validation is recommended
- `relevant_lines` for diff-scoped scans when the bug overlaps the diff and those lines are relevant to the bug
- taxonomy with CWE IDs when known
- enough evidence that a later reviewer can understand why the candidate is technically plausible before validation

For diff-scoped discovery, when candidates are emitted, create the per-finding directory from `../../references/scan-artifacts.md` and append one discovery receipt to that finding's candidate ledger. The ledger row should identify the candidate, scan scope, discovery status, affected locations, and the discovery artifact or evidence that produced it.


## Hard Rules

- Use the tools to examine repository files before making decisions.
- Focus on the actual changes, not the commit message.
- Stay anchored to the diff and the files it relies on for diff-scoped scans.
- Candidate discovery is about plausibility, not final severity.
- For diff-scoped discovery, do not emit an untracked candidate. Every candidate finding needs a stable candidate id and a discovery receipt in its candidate-ledger path from `../../references/scan-artifacts.md` so later validation and attack-path analysis can prove coverage for that exact finding.
- Do not add `relevant_lines` when no bug exists. For diff-scoped scans, add `relevant_lines` only when the bug overlaps the diff and those lines are relevant to the bug.
- Do not turn discovery into full validation or full severity calibration.
- Continue reviewing until no additional distinct plausible candidates remain.
- For diff-scoped discovery, save a final visible report using the finding discovery report path from `../../references/scan-artifacts.md`.
