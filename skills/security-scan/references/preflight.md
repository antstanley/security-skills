# Scan Preflight

Top-level scan skills run this read-only helper before substantive scan work. It answers one question: can this session honestly run the requested scan mode?

To launch the preflight itself, resolve `<python_command>` to the configured Python interpreter (`$PYTHON` when one is provided), otherwise `python` on Windows and `python3` on Unix-like hosts. For every later helper command, prefer the preflight's reported `resolved.pythonCommand`, which resolves in this order: `$PYTHON`, then the interpreter that ran the preflight (`sys.executable`), then the platform default above.

```text
<python_command> <skill_root>/scripts/preflight.py --profile <capability-profile> --target <scan-target-directory> --runtime-check delegation_available=<true|false> [--worker-slots <count>] --available-skill <skill-name>
```

Profiles are `security_scan`, `security_diff_scan`, and `deep_security_scan`.

## Supplying Runtime Facts

Inspect the current tool surface once before building the command, and pass everything you learned on the first invocation. Do not omit a fact you already have and wait for an `incomplete` result.

- `--runtime-check delegation_available=true` when a usable subagent dispatch tool is available, `false` when it is not. If tool schemas are deferred, search the deferred tool list before passing `false`. Pass `false` only after discovery fails to expose a usable delegation tool.
- `--worker-slots <count>` for the number of subagents this session can run concurrently. Only the deep profile evaluates it. Omit it rather than guessing.
- `--available-skill <skill-name>` once per installed security skill, using skill names such as `validation`. Take these from the session's available-skills list, not from files on disk. Do not pass unrelated session skills. All three profiles require the four phase skills (`threat-model`, `finding-discovery`, `validation`, `attack-path-analysis`); the diff and deep profiles additionally require the mandated tail skills `vulnerability-writeup` and `propose-security-hardening`, and the deep profile requires `security-scan`.

A passed `delegated_workers` check means the runtime supports delegation and the explicitly invoked scan authorizes it. A worker-slot result is the available maximum, not a promise that every worker will start. If delegation is unavailable, continue on the documented parent fallback and do not describe configured slots as running workers or as reduced coverage.

## Where To Run It

Run the helper directly in the parent. It is a short read-only command, and keeping it in the parent keeps the exact command, exit code, and JSON result in the session transcript rather than attributing an unobservable child result to the active runtime.

## Reading The Result

Use the helper result as the preflight source of truth. Do not independently reinterpret profile requirements.

Requirement severities:

- `block`: the requested workflow cannot be claimed honestly when unmet
- `warn`: the workflow can continue only on the documented degraded path
- `suggest`: the workflow can continue, but mention the improvement when it materially affects scan quality or resumability

Top-level statuses:

- `ready`: continue. Explain `warn` or `suggest` issues when they materially affect scan quality, capacity, or resumability, and use the documented degraded path.
- `blocked`: a required capability failed. Follow the remediation handling below.
- `incomplete`: a required capability is unknown. Establish it from the current tool surface and rerun with an explicit `--runtime-check` or `--available-skill`. Do not treat an unknown value as evidence that the capability is available.

The `resolved` object carries facts later phases need: `pythonCommand`, the resolved `target`, `repoRoot` for diff scans, `scanRoot`, and `stateDir`. Prefer these over re-deriving the same paths.

## Handling A Non-Ready Result

Each failing result carries a concrete `remediation` string. Present the exact reasons and the remediation, then choose a control based on whether the session can actually pause for a human reply.

Treat headless runs, automation, and any host that cannot pause as non-interactive. In a non-interactive session, do not ask; apply only remediation you can perform without user approval, rerun the preflight once, and continue only if it becomes `ready`. If it does not, report the exact remaining blocker and stop.

In an interactive session, use the host's available user-input tool, or ask directly
if no suitable tool exists. Present the concrete remediation and let the user
choose to apply it and retry, leave the scan paused, or cancel. Use a permission
approval flow for actions requiring permission; a missing reply is not approval.

Stop for the answer before recording the scan objective or starting substantive analysis. Apply only the approved remediation after **Apply and retry**, preserve the scan and stop after **Leave paused**, and stop with a concise cancellation note after **Cancel scan**.

Never write outside the state directory while remediating, and never invent a patch the helper did not report.

## Degraded Paths

- No delegation: run every phase in the parent thread. Coverage is unchanged; wall-clock is longer. Say so once in the scan summary.
- Fewer worker slots than the deep profile wants: run fewer concurrent discovery passes. Report the reduced concurrency in the scan summary rather than silently narrowing discovery.
- Unwritable scan root or state directory: this is a hard blocker. Ask for a writable location through `SECURITY_SCAN_ROOT` or `SECURITY_STATE_DIR` instead of writing into the repository under review.

Do not warn merely because the environment differs from the recommended setup. Warn or block only when an evaluated capability requirement is unmet.
