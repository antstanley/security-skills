# Static Finding Assessment

Use this reference when a Security workflow needs static repository evidence to support or defeat a supplied security claim.

This is not a top-level workflow. It does not define input normalization,
user-facing verdicts, scan ledgers, dynamic validation methods, or fix behavior.
The calling skill owns those contracts. It does own the shared confidence scale
below, which covers both static and dynamic evidence.

## Assessment Tuple

For each claim, identify the smallest useful tuple:

- source: the attacker-controlled input, external trigger, or trusted operator input named by the claim
- control: the relevant guard, validator, sanitizer, authorization check,
  configuration gate, feature flag, or missing security control
- sink: the dangerous operation, vulnerable dependency, broken control, or impact point
- reachable path: the code/config path that connects source, control, and sink under stated preconditions
- boundary: the product surface and trust boundary that make the path security relevant
- counterevidence: static facts that weaken, defeat, or scope the claim
- proof gaps: missing facts that prevent a stronger conclusion

Do not treat dependency presence, string matches, or a partial call chain as a complete assessment. A useful static assessment explains both what was found and what remains unproven.

## Evidence Search Order

Inspect the smallest relevant evidence set before broadening:

1. User-provided locations, scanner locations, advisory references, or SARIF result locations.
2. Dependency manifests, lockfiles, package exports, binary entrypoints, build metadata, deploy configs, and generated-artifact boundaries.
3. Affected functions, call sites, routes, RPC handlers, parser entrypoints,
   CLI commands, plugin hooks, message consumers, and package APIs.
4. Nearby guards, validators, sanitizers, authorization checks, feature flags,
   configuration checks, and compensating controls.
5. Product-surface evidence such as `SECURITY.md`, supported-version docs,
   disclosure policy, threat models, product docs, deploy files, comments, and tests that clarify intended behavior.

Prefer precise repository references over broad claims. If evidence is absent,
record the absence as a proof gap unless the absence itself defeats the claim.

## Boundary And Surface Checks

Before treating a static path as security-relevant, classify:

- product surface: hosted service, library API, CLI, local developer UI,
  MCP/tooling surface, plugin hook, example/demo, test/fixture, docs, generated code, vendored code, or unknown
- source trust: untrusted user input, tenant/user-controlled data, remote attacker input, trusted operator input, trusted developer configuration,
  local-only input, intentionally code-executing extension point, or unknown
- policy basis: repository policy, product docs, deploy/config evidence,
  package metadata, code comments, threat model, or unknown

Check whether untrusted input can reach the bug.

## Confidence Scale

This is the single confidence scale for Security workflows. Validation, triage,
and the canonical `confidence.level` in `findings.json` all use these three
levels; the final report's `Confidence Scale` table summarizes the same scale.
Calibrate from the strongest evidence actually obtained, not from how dangerous
the bug class sounds.

- high: either of these, with no material unresolved reachability or
  exploitability blocker:
  - a complete, exact static source/control/sink path with stated preconditions,
    relevant boundary evidence, and no material unresolved counterevidence
  - a dynamic reproduction against the actual target code that demonstrates the
    vulnerable behavior: a crashing PoC, a valgrind or ASan report, a
    non-interactive debugger trace of the source-to-sink path, a focused unit or
    integration test that asserts the vulnerable behavior, or an end-to-end
    reproduction through the real interface (for a web bug, crafted HTTP
    requests against the running application whose responses or side effects
    show the vulnerable outcome; likewise for CLI, file, RPC, message, or
    package-API interfaces)
- medium: a plausible path with some direct evidence, but incomplete call-chain,
  config, version, deployment, role-reachability, type-constraint, or
  exploit-reliability evidence; or a dynamic attempt that exercised part of the
  path but stopped short of showing the vulnerable outcome
- low: weak or indirect support, significant ambiguity, or missing repository
  context

Dynamic reproduction is the strongest evidence. When a workflow has both a
static trace and a dynamic reproduction, cite the reproduction in the confidence
rationale. A complete static trace is not lowered merely because runtime proof
was not attempted or the environment could not be brought up; record that as a
proof gap, and lower confidence only when the gap leaves a real reachability,
configuration, or exploitability question open.

Counterevidence that clearly defeats the claim is not a confidence level. The
calling skill records it with its own suppression or rejection outcome.

Use proof gaps instead of filling in missing runtime, environment, policy, or deployment facts.

## Output Ingredients

The calling skill decides the final schema and labels. The static assessment should provide enough ingredients for that output:

- concise rationale
- source, control, sink, and reachable path when established
- affected locations with exact repository paths and line references when available
- boundary assessment and policy basis
- supporting evidence
- counterevidence
- proof gaps
- confidence from the confidence scale above
- minimal next step when static evidence cannot settle the claim
