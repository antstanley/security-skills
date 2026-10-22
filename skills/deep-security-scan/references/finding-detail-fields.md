# Rich Finding Detail Fields

For every reportable finding in `findings.json`, preserve the validated reasoning and the exact source snippets that prove it. Downstream consumers render these fields directly; nothing recovers missing analysis from `report.md` or reads source files after the scan.

## Writing Rules

- Wrap RPC names, functions, types, fields, parameters, configuration keys, literal identifiers, and short expressions in single backticks. For example: `POST /archives`, `member.name`, `dest_root`, and `extract_archive()`.
- Keep code out of prose. Put source snippets in `codeEvidence[].code`, then reference them from the section that explains why the snippet matters. Consumers consolidate those referenced snippets under **Root cause** so the violated invariant and its source proof stay together.
- Root cause must be a source-backed walkthrough, not a verdict paragraph. Start with the code where user-controlled data is declared, decoded, or read; follow each meaningful call, transformation, or state transition; then show the missing control, dangerous operation, and later consumer when it affects impact.
- Give each code-evidence item a stable `id`, a concise `label`, an exact source location, the smallest useful snippet, a `role`, and an `explanation`. Supported roles include `user_input`, `entrypoint`, `propagation`, `root_control`, `sink`, `outcome`, and `expected_control`.
- Write each `explanation` as connective reasoning: identify the attacker-controlled value at this step, say which callee or state receives it next, and explain why the shown lines preserve or violate the expected invariant.
- Order `rootCause.evidenceRefs` from user input to outcome. Put an `expected_control` comparison after the vulnerable call-stack refs; it is supporting context, not a step in the vulnerable stack. Omit incidental helpers that do not carry the value or enforce the relevant boundary.
- Do not use location-only filler such as "the root cause is tied to the broken control at path:line." The source table already records locations. Explain the violated invariant and show the code that violates it.
- Validation must connect attacker-controlled input, the missing or bypassed control, and the security-relevant state change or sink. Do not replace that proof with a list of file names and line numbers.
- Attack-path analysis must be concise. Record the realistic attacker boundary, the minimum trigger sequence, and the concrete outcome. Use code evidence for the important transitions instead of repeating the full validation narrative.
- Populate only evidence-backed fields. Omit unknown values instead of adding placeholders.

## Concise Finding Projection

The finding detail view is a decision-focused projection of the canonical finding, not a copy of the full `vulnerability-writeup` report. Preserve the parts of that report that a reviewer needs to understand and act on the issue:

- the validation method, direct observations, confidence rationale, and remaining uncertainty;
- dataflow source, meaningful transformations, dangerous sink, and concrete outcome;
- realistic attacker, entry point, access requirements, preconditions, and attacker outcome;
- severity rationale plus the specific evidence that would raise or lower the rating;
- the minimal remediation invariant, regression tests, and preventive controls.

Keep background exposition, alternate exploit research, full PoC instructions, representative command output, and long source walkthroughs in the detailed write-up. Do not copy them into canonical fields merely to make the finding longer. The finding should stay self-contained enough to support triage while avoiding duplicated or speculative prose.

Treat recorded artifacts as a navigator, not another source-proof section. When `writeup.reportPath` is present, it names a verified scan-local report whose sibling `poc/` directory holds the supporting regular files. Do not place artifact paths in root-cause prose or add an unvalidated artifact list to the canonical finding merely for display.

## Structured Example

The following shape shows how to encode the archive-extraction path-traversal finding from `src/examples/completed-scan/` in the source repository:

```json
{
  "summary": "The `POST /archives` upload handler passes the uploaded archive to `extract_archive()`, which joins each attacker-controlled `member.name` onto `dest_root` and writes without a containment check, so a member named `../../etc/cron.d/job` escapes the extraction root.",
  "codeEvidence": [
    {
      "id": "upload-input",
      "label": "Attacker-controlled archive upload",
      "path": "src/upload.py",
      "startLine": 18,
      "endLine": 23,
      "language": "python",
      "role": "user_input",
      "code": "@app.post(\"/archives\")\ndef upload_archive():\n    archive = request.files[\"archive\"]\n    return extract_archive(archive.stream, DEST_ROOT)",
      "explanation": "The uploaded archive bytes, including every member name, are attacker-controlled and flow directly into `extract_archive()`."
    },
    {
      "id": "member-join",
      "label": "Member name joined without containment",
      "path": "src/extract.py",
      "startLine": 37,
      "endLine": 40,
      "language": "python",
      "role": "root_control",
      "code": "for member in tar.getmembers():\n    destination = os.path.join(dest_root, member.name)",
      "explanation": "`member.name` is joined onto `dest_root` verbatim; nothing normalizes the result or rejects `..` segments, so the joined path can leave `dest_root`."
    },
    {
      "id": "member-write",
      "label": "Filesystem write at the joined path",
      "path": "src/extract.py",
      "startLine": 41,
      "endLine": 44,
      "language": "python",
      "role": "sink",
      "code": "    with open(destination, \"wb\") as handle:\n        handle.write(tar.extractfile(member).read())",
      "explanation": "The write happens at the unvalidated joined path, so the attacker-chosen suffix decides which file is created or overwritten."
    },
    {
      "id": "expected-containment",
      "label": "Containment used by the sibling download helper",
      "path": "src/download.py",
      "startLine": 29,
      "endLine": 33,
      "language": "python",
      "role": "expected_control",
      "code": "resolved = os.path.realpath(candidate)\nif not resolved.startswith(os.path.realpath(base) + os.sep):\n    raise ValueError(\"path escapes the base directory\")",
      "explanation": "The sibling download helper shows the expected invariant: resolve the candidate path and reject anything outside the base directory before touching the filesystem."
    }
  ],
  "rootCause": {
    "summary": "The violated invariant is that every extracted member must resolve inside `dest_root`. `extract_archive()` joins the attacker-controlled `member.name` onto `dest_root` and writes without the resolve-and-contain check the sibling download helper applies.",
    "evidenceRefs": [
      "upload-input",
      "member-join",
      "member-write",
      "expected-containment"
    ]
  },
  "validation": {
    "method": "static source trace",
    "summary": "The source trace confirms uploaded member names reach the join and write with no normalization, containment check, or member-name filter on the path.",
    "evidenceRefs": [
      "upload-input",
      "member-join",
      "member-write"
    ],
    "assertions": [
      "No caller of `extract_archive()` prevalidates member names.",
      "A member named `../../escape.txt` produces a destination outside `dest_root`."
    ],
    "limitations": [
      "The finding was validated by source review; no crafted archive was executed against a running instance."
    ]
  },
  "attackPath": {
    "summary": "An attacker uploads a crafted archive to `POST /archives` with a member named `../../etc/cron.d/job`; extraction writes the attacker's file content outside the extraction root.",
    "dataflow": {
      "summary": "uploaded archive -> `upload_archive()` -> `extract_archive()` member loop -> `os.path.join(dest_root, member.name)` -> filesystem write",
      "source": "attacker-controlled archive member names",
      "sink": "the `open(destination, \"wb\")` write",
      "outcome": "file creation or overwrite at an attacker-chosen path outside `dest_root`",
      "evidenceRefs": [
        "upload-input",
        "member-join",
        "member-write"
      ]
    },
    "reachability": {
      "summary": "Any client able to reach the upload endpoint controls the archive bytes; no privileged role or unusual configuration is required.",
      "attacker": "authenticated upload-endpoint client",
      "entrypoint": "`POST /archives`",
      "outcome": "arbitrary file write with the service's filesystem privileges"
    },
    "evidenceRefs": [
      "member-join",
      "member-write"
    ],
    "impact": {
      "level": "high",
      "why": "An arbitrary file write with service privileges can overwrite trusted configuration or scheduled-job definitions."
    },
    "likelihood": {
      "level": "high",
      "why": "Crafting a traversal member name is trivial and the endpoint is part of the ordinary product surface."
    },
    "limitations": [
      "Write privileges are bounded by the service account's filesystem permissions."
    ]
  }
}
```

## How The Report Renders These Fields

The generated report shows each documented field in a fixed place:

- **Validation**: `validation.summary`, `validation.method`, the code evidence in `validation.evidenceRefs`, `validation.assertions` as a list of checks, and `validation.limitations` as counterevidence and remaining uncertainty. The remaining-uncertainty list is always shown; when nothing was recorded it says so.
- **Dataflow**: `attackPath.dataflow` summary, source, sink, outcome, and transformations, followed by the code evidence in `attackPath.evidenceRefs`.
- **Reachability**: `attackPath.summary`, then the `attackPath.reachability` summary, attacker, entry point, outcome, and preconditions, then `attackPath.limitations`.
- **Severity**: `severity.rationale`, then the `why` of `attackPath.impact` and `attackPath.likelihood` as supporting rationale, then `severity.changeConditions`. The impact and likelihood levels are severity inputs and are not shown as separate labels.

Two older validation fields remain supported for compatibility. New producers should use the documented fields above instead:

- `validation.evidence`: a list of short evidence statements, or one string. The report lists them under `Evidence`.
- `validation.counterEvidence`: a list of counterevidence statements, or one string. The report lists them with `validation.limitations` as remaining uncertainty.

`rootCause.code` and `rootCause.language` remain supported for older producers that can provide only one snippet. New producers should use the shared `codeEvidence` catalog, assign call-stack roles, and order `rootCause.evidenceRefs` from input to outcome so the same exact source can support Root Cause, Validation, and Attack-path analysis without copying it into several fields.
