# security-skills

Thirteen security skills for coding agents: repository and diff scans, threat modelling, validation, attack-path analysis, triage, remediation, and reporting. They run in Claude Code, Codex, and any harness that reads the Agent Skills format.

> **Not published yet.** The install commands below point at `github.com/antstanley/security-skills`, which does not exist yet. They will work once the repo is pushed there. Until then, use the standalone installer from a local clone (`sh install.sh`).

## Install in one step

Pick the route that matches your agent:

| You use | Run this |
| --- | --- |
| Claude Code | `/plugin marketplace add antstanley/security-skills` then `/plugin install security@security-skills` |
| Codex | `codex plugin marketplace add antstanley/security-skills` then `codex plugin add security@security-skills` |
| Any harness, via the Vercel `skills` CLI | `npx skills add antstanley/security-skills` |
| Any harness, standalone | `curl -fsSL https://raw.githubusercontent.com/antstanley/security-skills/main/install.sh \| sh` |

Start a new session after installing so the agent picks up the skills.

## The four ways to install

### 1. Claude Code plugin

Claude Code reads the marketplace in `.claude-plugin/marketplace.json`, which lists one plugin, `security`, that points at the repo root.

```text
/plugin marketplace add antstanley/security-skills
/plugin install security@security-skills
```


### 2. Codex plugin

Codex reads `.agents/plugins/marketplace.json`. The plugin manifest is `.codex-plugin/plugin.json`, and it exposes `./skills/`.

```sh
codex plugin marketplace add antstanley/security-skills
codex plugin add security@security-skills
```

### 3. Vercel `skills` CLI

The [`skills`](https://github.com/vercel-labs/skills) CLI finds every `skills/<name>/SKILL.md` in the repo and copies each skill folder to the agents you choose. It requires Node.js 22.20 or later.

```sh
npx skills add antstanley/security-skills              # pick skills and agents interactively
npx skills add antstanley/security-skills --list       # see what is available
npx skills add antstanley/security-skills --skill security-scan    # one skill (names from --list)
npx skills add antstanley/security-skills -g           # install globally, not per project
```

Each skill folder is self-contained, so a single skill works on its own.

### 4. Standalone installer (`install.sh`)

`install.sh` is plain POSIX `sh`. It runs under `sh`, `dash`, or `bash`. Run it from a clone, or pipe it from the web:

```sh
curl -fsSL https://raw.githubusercontent.com/antstanley/security-skills/main/install.sh | sh
sh install.sh                                    # from a clone of this repo
```

With no flags and a terminal attached, it asks two questions: which skills to install (numbers, names, or `all`), and where to put them.

| Destination | Use it for |
| --- | --- |
| `~/.agents/skills` | Codex, Cursor, OpenCode, Zed, and other Agent Skills harnesses |
| `~/.claude/skills` | Claude Code, outside the plugin system |
| `./.agents/skills` | This project only |
| `./.claude/skills` | This project only, Claude Code |
| any path | You type it |

Options:

| Option | Effect |
| --- | --- |
| `--skills LIST` | Comma-separated skill names, or `all`. Skips the skill prompt. An empty value is an error. |
| `--dest DIR` | Install into `DIR`. Skips the destination prompt. An empty value is an error. |
| `--yes` | No prompts. Installs all skills to `~/.agents/skills`, or to `--dest` if given. Use this in scripts and when there is no terminal. |
| `--list` | Print every skill with its description, then exit. |
| `--dry-run` | Print what would be copied. Change nothing. |
| `--force` | Replace folders the installer did not create. Without it, those folders are skipped. The installer still refuses a destination that is, contains, or sits inside the source `skills/` folder. |
| `--ref REF` | Git ref to download when not run from a clone. Default `main`. |
| `-h`, `--help` | Show the built-in help. |

Environment variables:

| Variable | Effect |
| --- | --- |
| `SECURITY_SKILLS_REPO` | `owner/name` to download from. Default `antstanley/security-skills`. |
| `SECURITY_SKILLS_ARCHIVE` | Path to a local `.tar.gz` of the repo. Skips the download. Useful offline or for testing. |

Installed folders get a marker file, `.installed-by-security-skills`. Re-running the installer replaces each folder it installed with the current version. Each skill is copied into a staging folder beside the destination first and swapped in only after the copy succeeds, so a failed copy leaves the previous version in place. Edits you made inside those folders are lost, so keep local changes elsewhere.

Examples:

```sh
sh install.sh --list
sh install.sh --yes --skills security-scan,validation --dest ~/.agents/skills
sh install.sh --yes --dry-run
sh install.sh --yes --force --dest ~/.claude/skills
```

## The skills

The 13 skills split into three groups. Scan entry points run the whole workflow. Phases run one stage on its own. Follow-ups act on findings after a scan.

### Scan entry points

| Skill | What it does | Use it when |
| --- | --- | --- |
| `security-scan` | Standard single-pass audit of a repo or a scoped path. Threat model, discovery, validation, attack-path analysis, then a sealed report. | You want a normal security review of a whole repo or one directory. |
| `security-diff-scan` | Same pipeline, limited to a diff: a PR, commit, branch, or uncommitted patch. Needs Git. | You want to review a change before it lands. |
| `deep-security-scan` | Multi-pass, exhaustive scan. Repeats discovery in rounds until new passes stop finding anything. Needs subagents. | You want the most thorough pass and can accept a long run. |

### Phases

| Skill | What it does | Use it when |
| --- | --- | --- |
| `threat-model` | Builds or reuses the repo's threat model: trust boundaries, attacker-controlled inputs, assumptions. | You need the context that decides what counts as a real finding. |
| `finding-discovery` | Surfaces candidate findings across the in-scope files. | You want the raw list of suspicious code before any judgement. |
| `validation` | Decides whether each candidate is real, and tries to reproduce it where practical. | You want to separate real bugs from false positives. |
| `attack-path-analysis` | Traces source to sink and sets severity from reachability and impact. | You want to know how bad a validated finding really is. |

### Follow-up

| Skill | What it does | Use it when |
| --- | --- | --- |
| `triage-finding` | Static triage of findings you already have: SARIF, CVE or advisory reports, scanner tickets, Jira or Linear issues. Checks whether each one affects this repo. | You have a backlog of findings from another source. |
| `fix-finding` | Writes a minimal patch for one finding, applies it, and verifies it. | You want a fix for a validated finding. |
| `vulnerability-writeup` | Writes a detailed, source-backed report per finding, with a proof of concept where possible. | You need a report to hand to engineering or a disclosure. |
| `propose-security-hardening` | Proposes structural fixes that cover many findings at once, with trade-offs and an implementation plan. | Per-finding patches are not enough and you want a systemic fix. |
| `track-findings` | Files validated findings as Linear, Jira, or GitHub issues, or drafts GitHub security advisories. Shows the exact payload and asks for approval before writing; a batch of up to 25 issues is approved once, as one exact previewed list, then each write is read back. | You want findings in your tracker. |
| `define-security-policy` | Writes or updates the repo's `SECURITY.md`. Defines what is in scope, out of scope, and which properties must hold. | Scans keep flagging things that are out of scope, or the scope is unclear. |

## How a scan runs

1. **Preflight.** `scripts/preflight.py` checks the target, the phase skills it needs, whether subagents are available, and that the output directories are writable. It returns `ready`, `blocked`, or `incomplete`, each with a concrete fix.
2. **Phases.** Threat model, discovery, validation, then attack-path analysis. Each phase runs to full depth before the next one starts. Where subagents are available, discovery and per-candidate work fan out across them. Where they are not, the parent agent does the same work in order, with the same coverage. The one exception is `deep-security-scan`, which needs subagents and says so at preflight.
3. **Canonical JSON.** Findings and coverage are written to the schemas in `schemas/`.
4. **Finalize.** `scripts/finalize_scan_contract.py` validates and seals the bundle, then generates `report.md` and a SARIF export. A scan is not complete until this step succeeds.

Where output goes:

| Setting | Purpose | Default |
| --- | --- | --- |
| `SECURITY_SCAN_ROOT` | Where scan bundles are written. Nothing is written into the repo under review. | `$TMPDIR/security-scans` |
| `SECURITY_STATE_DIR` | Durable plugin state. | `$XDG_STATE_HOME/security-skills`, or `~/.local/state/security-skills` |
| `SECURITY_STARTED_AT` | Supplies `scan.startedAt` when the draft manifest omits it. It never sets `completedAt` or `sealedAt`; record `completedAt` in the draft for byte-identical repeated finalization of a draft. | unset |
| `PYTHON` | Interpreter for the helper scripts. | the preflight's own interpreter; in skills without a preflight, `python3` (`python` on Windows) |

A worked example bundle lives in `src/examples/completed-scan/`, with the three canonical JSON files and the generated report.

## What you need

- **Python 3.13 or later.** The helper scripts use only the standard library. Nothing to `pip install`.
- **Git**, for diff scans only.
- **Optional:** the `gh` CLI for GitHub intake and issue tracking, and MCP servers for Jira and Linear. Skills that need them stop with a clear message when they are missing.
- **Node.js 22.20 or later**, only for the Vercel `skills` route.

## Repository layout

```text
security-skills/
├── src/                          canonical source. Edit here.
│   ├── skills/<name>/SKILL.md    the 13 skills and their own references
│   ├── references/               shared guidance, copied into each skill that needs it
│   ├── scripts/                  helpers: preflight, finalize, normalize, validate, ...
│   ├── schemas/                  JSON Schemas for the sealed scan contract
│   ├── examples/completed-scan/  a worked, sealed bundle
│   └── ruff.toml
├── skills/                       GENERATED. One self-contained folder per skill.
│   └── <name>/                   SKILL.md plus the scripts, references, and schemas it needs
├── scripts/sync-skills.py        builds skills/ from src/ (stdlib only)
├── .claude-plugin/
│   ├── plugin.json               Claude Code plugin manifest
│   └── marketplace.json          Claude Code marketplace (lists the security plugin)
├── .codex-plugin/plugin.json     Codex plugin manifest (exposes ./skills/)
├── .agents/plugins/marketplace.json   Codex marketplace
├── install.sh                    standalone installer (POSIX sh)
└── LICENSE.md                    Apache-2.0, with the list of changes from upstream
```

Each skill folder is self-contained because installers copy one folder at a time. The Vercel CLI and `install.sh` both work this way. The generator copies in the shared references, scripts, and schemas each skill mentions, and rewrites `../../references/...` links to point at its own copies. Prose must name a helper by its `.py` file name to pull it in; a helper's own sibling imports and loads are followed automatically.

### Working on the skills

```sh
# edit src/, then regenerate skills/
python3 scripts/sync-skills.py

# verify skills/ matches src/ (exits 1 on drift, for CI)
python3 scripts/sync-skills.py --check
```

Never edit `skills/` by hand. The next regeneration overwrites your change.

## Harness- and model-agnostic design

Nothing in these skills depends on one agent harness or one model.

- **Skill root, not plugin root.** Each skill resolves `<skill_root>`, the folder containing its own `SKILL.md`. Every installed skill carries the scripts, references, and schemas it needs (not every skill needs all three), so the paths work wherever the skill is installed.
- **Subagents are optional.** A subagent is a delegated worker with its own context. The skills name the capability, not the tool. Where delegation is unavailable, the parent runs every phase in order with the same coverage, and preflight reports that as the documented fallback. `deep-security-scan` is the exception: it needs delegation and says so.
- **Companion skills by name.** Skills refer to each other by skill name. Each harness loads them through its own skill mechanism, or the agent reads the `SKILL.md` directly.
- **Questions and tasks.** Skills use the harness's prompt if it has one, and ask in plain text if not. Task tracking is used when available.
- **No model names.** The skills make no assumption about which model runs them.

## License and attribution

Apache License 2.0. See [LICENSE.md](LICENSE.md).

These skills are a fork of OpenAI's [codex-security](https://github.com/openai/codex-security) plugin (copyright 2025 OpenAI). The fork's changes are listed in `LICENSE.md`. The repo's own changes make the skills harness-neutral. Those changes are the `<skill_root>` layout, the generated self-contained folders, and the state directory now defaulting to `$XDG_STATE_HOME`.

## Known gaps

- **Not published.** The GitHub install commands above need the repo to be pushed to `antstanley/security-skills` first. The owner name is an assumption from the sibling repo.
- **No plugin icon yet.** The Claude plugin validator reports `ICON_MISSING`. `src/assets/logo.png` is 360 × 360 px, but the icon needs to be 512 to 2048 px square. Add a larger one as `.claude-plugin/icon.png`, or set `icon` in `plugin.json`.
- **Retired source.** The sibling `../skills` repo held these skills before this one. That repo is being retired, and this is a one-time migration. Changes now go into this repo only.
