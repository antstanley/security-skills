# Runtime and bundled resources

These skills contain plain instructions and helper scripts. They do not depend on one
agent harness or one model. The same skill content is packaged for Claude Code, Codex,
the Vercel `skills` CLI, and the standalone installer. Wherever a harness-specific
mechanism is useful, this guidance names the capability first and gives examples second.

## Skill root

`<skill_root>` is the directory that contains the `SKILL.md` you loaded. Every installed
skill carries the `scripts/`, `references/`, and `schemas/` it needs inside its own folder,
so `<skill_root>` always contains those three directories.

Resolve `<skill_root>` from the location of the loaded skill, not from the repository under
review and not from the shell's current directory. Substitute the absolute path into command
examples and quote it when invoking a helper.

## Helper scripts

Use the Python interpreter that preflight reports. Do not install dependencies or change
the target repository merely because the skills are installed. If a dependency is missing,
surface it concretely and follow the workflow's existing remediation rules.

## Companion skills

A notation such as `validation` in running text names another skill in this set by its
skill name. Load it through your harness's skill mechanism when one exists. If none exists,
read its `SKILL.md` from the installed skill folder and follow it. Do not report a required
capability as available solely because its file exists on disk.

## Subagents

A subagent is a delegated worker with its own context window. Start one with whatever
your harness provides for delegation, such as a sub-agent or task tool, an agent spawn
call, or a background worker. Use that mechanism's actual schema. Inherit model settings
unless you are authorized to override them, and keep workers distinct wherever the
workflow requires independent validation.

When your harness cannot delegate, the parent runs every phase itself, in order, with the
same coverage. Preflight records that case as the documented fallback, except for `deep-security-scan`, whose profile requires delegation and blocks without it.

## Task tracking and questions

Use a task tracker when your harness offers one. Otherwise state the objective in your
first visible update.

For questions, use your harness's user-input prompt when it has one. Otherwise ask in
plain text and wait for the reply. Preserve approval boundaries for external writes and
remediation. No response is not permission.
