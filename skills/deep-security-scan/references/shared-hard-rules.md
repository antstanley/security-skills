# Shared Hard Rules

Apply these rules for every Security scan before the scan-mode-specific hard rules in that workflow:

- Keep the phases separate.
- Follow the execution plan in order.
- Use the tools to inspect the repository before making decisions.
- Candidate-finding coverage is required. Compact-ledger modes — standard scans and the deep-scan centralized tail — prove it with the nested `validation` and `attack_path` records in the enriched candidate ledger, not with per-candidate receipts. In per-candidate-receipt modes — diff and resumed legacy scans — do not finalize a candidate finding until `<findings_dir>/<candidate_id>/candidate_ledger.jsonl` shows a discovery receipt and a validation receipt, plus an attack-path receipt when validation left the candidate `reportable` or `deferred`, or an explicit deferred reason for the missing proof. Candidates closed at validation as `suppressed` or `not_applicable` owe discovery and validation receipts only.
- Avoid destructive commands, interactive editors, and broad unbounded scans.
- Prefer targeted, reversible shell commands.
- Abandoning a scan is terminal and cannot be resumed. Do it only for an unrecoverable blocker after documented recovery is exhausted, or when the user explicitly cancels. Do not abandon a scan merely because work remains, subagents are still running, partial artifacts exist, or a turn or context window is ending. Record meaningful progress in the scan directory and leave it intact so a later continuation can resume.
- For Phase 1 fallback threat model generation, produce a repository-level threat model that would still make sense for an unrelated diff in the same repository.
- Do not let the current scan target bias Phase 1 unless the user explicitly requests a target-scoped threat model.
- For later phases, stay grounded in repository evidence and the actual in-scope code.
- Do not emit a finding unless it survives the final policy-adjustment pass.
