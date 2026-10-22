# Attack Path Facts Guidance

Use this guidance during attack-path analysis before severity calibration.

## Attack Path Facts

Gather the attack-path facts in structured form during analysis, then feed them into the canonical outputs rather than a report section. The final `report.md` is a deterministic projection and never contains an `Attack Path Facts` section: the model does not author the report, and the projection folds these facts into each finding's Reachability and Severity prose. Record them in:

- the compact nested `attack_path` record (`dataflow`, `reachability`, `counterevidence`, `impact`, `likelihood`, `severity`, `severity_rationale`, `change_conditions`) in compact standard-scan mode
- the canonical finding fields `attackPath.dataflow`, `attackPath.reachability`, `attackPath.summary`, `severity.rationale`, and `severity.changeConditions` when assembling `findings.json`
- the phase report and attack-path receipt in per-candidate-receipt modes

The gathered facts should explicitly cover:

- Assumptions
- Context:
  - whether the impact is self-only or crosses a meaningful boundary
  - the repository evidence for that conclusion
- In-Scope Status According to the Threat Model:
  - whether the component is in scope
  - the reasoning
- Exposure:
  - whether the surface is public
  - ports, ingress, and load-balancer type when repository evidence exists
  - the evidence
- Identity:
  - service account or managed identity if present
  - effective privileges
- Cross-Boundary Behavior:
  - whether a boundary crossing is actually verified
  - the evidence chain
- Vector:
  - `remote`, `local_network`, `localhost`, `none`, or `unknown`
  - the evidence
- Preconditions:
  - what the attacker needs
  - whether those preconditions are plausible, unlikely, unachievable, or unknown
  - the evidence
- Attacker Input Control:
  - whether attacker control is yes, plausible, no, or unknown
  - the evidence
- Category
- Mitigations Already Present
- Auth Scope:
  - whether the path is public, internal-only, admin-only, or unknown
  - the evidence
- Impact Surface:
  - build, runtime, data, identity, network, or other
  - the evidence
- Target Reach:
  - single service, base image, fleet, or unknown
  - the evidence
- Secrets References:
  - the secret type and reference chain when present
- Counterevidence:
  - the strongest conflicting repository evidence for the reportability-driving facts
  - why that evidence is or is not dispositive
- Blindspots
- Controls
- Confidence

Prefer concise prose values over a raw schema dump when filling those fields. The recorded facts must make the scoping and reportability conclusions easy to inspect from the canonical JSON alone, including:

- whether the finding is in scope according to the threat model
- whether the surface is public, internal, admin-only, localhost-only, or unknown
- what attacker-controlled input exists
- what preconditions the attacker needs and whether they are achievable
- whether a real trust boundary is crossed
- what identities, privileges, or secrets are involved
- what mitigations and controls already exist
- what the strongest repository counterevidence is
- what blindspots or residual uncertainty remain

Also make sure the recorded phase output carries forward:

- the factual attack path as ordered attacker steps in the dataflow and reachability narratives
- the reachability and scoping logic
- the strongest conflicting repository evidence in the counterevidence field
- the final policy decision after suppression
- the reasoning behind impact and likelihood in the severity rationale
