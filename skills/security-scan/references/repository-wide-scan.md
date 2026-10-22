# Standard Repository Or Scoped-Path Review

Use this procedure for a standard repository or scoped-path scan. Review every file, collect candidates in one ledger, then validate and check reachability in two compact passes over that ledger. Do not use ranking or multi-stage queues.

When the request or scan context includes CVE, GHSA, advisory, issue, release, package-version, or explicit vulnerability-family identifiers, run the advisory seed pass from `references/scan-artifacts.md` first (`seed_research.md`) and use its leads to focus detection. The seed pass is the one exception to the single-ledger flow below.

## File Inventory And Progress

Create the file list before review, with `<repo_root>` and `<scope>` taken from the preflight's `resolved.repoRoot` and `resolved.scope`. The repository under review must not be able to hide files from this list, so do not use a listing that honours `.gitignore`, `.ignore`, `.rgignore`, or tool configuration.

When `resolved.repoKind` is `git`, list every tracked file, including tracked files that match an ignore rule and files in initialized submodules, plus untracked files that are not ignored:

```text
mkdir -p "<discovery_dir>"
(cd "<repo_root>" && {
  git --literal-pathspecs -c core.fsmonitor=false ls-files -z --cached --recurse-submodules -- "<scope>"
  git --literal-pathspecs -c core.fsmonitor=false ls-files -z --others --exclude-standard -- "<scope>"
} | xargs -0 sh -c 'for p do if [ -f "$p" ] && [ ! -L "$p" ]; then printf "%s\n" "$p"; fi; done' sh | LC_ALL=C sort -u) > "<discovery_dir>/in_scope_files.txt"
```

When `resolved.repoKind` is `directory`, list every file without consulting any ignore file:

```text
mkdir -p "<discovery_dir>"
(cd "<repo_root>" && rg --files --hidden --no-ignore --no-config --glob '!.git/**' -- "<scope>" | sed 's#^\./##' | LC_ALL=C sort) > "<discovery_dir>/in_scope_files.txt"
```

Both commands write one repository-relative path per line and keep only regular files, so symlinks, deleted index entries, and special files drop out. A file name containing a newline cannot be listed this way, and Git lists an untracked nested repository as a single `path/` entry that the filter drops. Record any such path as a coverage gap rather than skipping it silently.

Every exclusion is a deliberate scan decision, never a side effect of the listing. When you leave in-scope files out of review, such as vendored dependencies or generated bundles the user asked to skip, record each one in coverage as an explicit exclusion with a pattern and reason.

Keep repository-relative paths in artifacts. Do not skip a file just because it is educational, an example, a demo, a fixture, or a test. Include it when it contains runnable behavior such as a route, parser, or template. List binary or generated files that could not be reviewed. Because every file is reviewed, do not create ranking or deep-review worklists.

## Discover And Combine Once

Review every listed file from start to finish. Read nearby code when needed to understand it. Look for unsafe command execution, unsafe parsing, XSS, attacker-controlled network requests, unsafe file access, and missing permission checks. Do not ignore a clear bug because another issue seems more important.

Do not stop reviewing a file after finding one bug.

Write raw candidates to one or more temporary JSONL files, then combine them:

```text
<python_command> <skill_root>/scripts/normalize_candidates.py --input <candidate-source> [<candidate-source> ...] --out <discovery_dir>/candidate_ledger.jsonl --repo-root <repo_root> --in-scope-files <discovery_dir>/in_scope_files.txt
```

Each raw candidate row uses only these fields:

- `cwe_ids`: an array of `CWE-<positive integer>` strings, which may be empty.
- `locations`: an array of repository-relative `path`, positive `start_line`, optional `end_line`, and `role`. The role is one of `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one location must be in `in_scope_files.txt`; supporting locations may be elsewhere in the repository.
- `summary` and `evidence`: concise text describing the possible bug and the code path.
- optional `context`: concise text that may help the review.
- optional `instance`: a short label for separate bugs that share the same locations, such as different request parameters or operations.

The combiner validates this shape and merges rows that describe the same bug: a primary location (`root_control` or `sink`, or every location when a row has neither) in the same file with an overlapping line range, CWE sets that share an id or are both empty, and no conflicting explicit `instance` labels. Merged rows take the union of CWE ids and locations, keep every text, list contributing input rows in `sources`, and keep the `candidate_id` of their first row, so ids stay deterministic. Pass `--rejects <path>` to skip and record invalid rows instead of failing the whole merge. It does not infer a status or decide whether a candidate is a bug. `candidate_ledger.jsonl` is the sole durable candidate artifact for a standard scan. Do not create one ledger or report per candidate, validation or attack-path queues, duplicate reports, or repeated receipts.

After normalization, freeze every discovery field, including `candidate_id`, `locations`, and `instance`. The two compact phase passes below may only add their nested records. When validation expands a broad family row into independently triggerable children, it records them in the nested record's `children` array defined in `references/scan-artifacts.md` instead of splitting or editing rows. Rewrite the ledger atomically and preserve its row order. Never feed an enriched ledger back through `normalize_candidates.py`; that script accepts raw discovery rows only.

## Validate And Check Reachability

Run `validation` once over the complete ledger in compact standard-scan mode. It must add a `validation` record to every row and preserve separate bugs, including bugs reachable through different routes or code paths. Do not dismiss a real bug just because the code is a demo, test, or only runs locally.

Then run `attack-path-analysis` once in compact standard-scan mode over validation rows with disposition `reportable` or `deferred`. It must add an `attack_path` record to every row that enters the phase, preserve exact affected locations, and use the threat model to decide realistic reachability and severity. A neighboring finding does not close the current candidate.

Build canonical findings and coverage from the file list and enriched candidate decisions using the ordered mapping in `references/final-report.md`. Include all relevant code locations in each finding. Map each validation child to its own finding or coverage outcome as `final-report.md` describes.
