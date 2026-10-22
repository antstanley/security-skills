#!/bin/sh
#
# install.sh — install the security skills into a coding agent's skill directory.
#
# Works as a one-liner and from a checkout:
#
#   curl -fsSL https://raw.githubusercontent.com/antstanley/security-skills/main/install.sh | sh
#   sh install.sh                      # from a clone of this repository
#
# It is plain POSIX sh, so it runs under sh, dash, or bash. Interactive prompts
# read from /dev/tty, so they still work when the script arrives on stdin.
#
# Every skill is a self-contained folder (SKILL.md plus the scripts, references,
# and schemas it needs). The installer copies whole folders and nothing else.
#
# Options:
#   --skills LIST    comma-separated skill names, or "all" (default in --yes mode)
#   --dest DIR       install into DIR (skips the destination prompt)
#   --yes            no prompts: install all skills to the default destination
#                    (or --dest) unless --skills narrows them
#   --list           print the available skills and exit
#   --ref REF        git ref to download when not run from a checkout (default: main)
#   --force          replace folders that were not installed by this script
#   --dry-run        print what would be copied, change nothing
#   -h, --help       show this help
#
# Environment:
#   SECURITY_SKILLS_REPO      owner/name to download from (default: antstanley/security-skills)
#   SECURITY_SKILLS_ARCHIVE   path to a local .tar.gz of the repository (skips the download)
#
set -eu

REPO="${SECURITY_SKILLS_REPO:-antstanley/security-skills}"
REF="main"
MARKER=".installed-by-security-skills"

skills_arg=""
dest_arg=""
assume_yes=0
list_only=0
force=0
dry_run=0

die() { printf 'install.sh: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1"; }

usage() {
  # Literal text, so help works when the script arrives on stdin ($0 is "sh").
  cat <<'EOF'
install.sh — install the security skills into a coding agent's skill directory.

Usage:
  curl -fsSL https://raw.githubusercontent.com/antstanley/security-skills/main/install.sh | sh
  sh install.sh [options]

Options:
  --skills LIST    comma-separated skill names, or "all" (default in --yes mode)
  --dest DIR       install into DIR (skips the destination prompt)
  --yes            no prompts: install all skills to ~/.agents/skills, or to --dest
  --list           print the available skills and exit
  --ref REF        git ref to download when not run from a clone (default: main)
  --force          replace folders this script did not install
  --dry-run        print what would be copied, change nothing
  -h, --help       show this help

Environment:
  SECURITY_SKILLS_REPO      owner/name to download from (default: antstanley/security-skills)
  SECURITY_SKILLS_ARCHIVE   path to a local .tar.gz of the repository (skips the download)
EOF
  exit 0
}

# --- parse arguments ----------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --skills)  [ $# -ge 2 ] || die "--skills needs a value"; skills_arg="$2"; shift 2 ;;
    --dest)    [ $# -ge 2 ] || die "--dest needs a value"; dest_arg="$2"; shift 2 ;;
    --ref)     [ $# -ge 2 ] || die "--ref needs a value"; REF="$2"; shift 2 ;;
    --yes|-y)  assume_yes=1; shift ;;
    --list)    list_only=1; shift ;;
    --force)   force=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# --- locate the skills -------------------------------------------------------
# Prefer a checkout next to this script; otherwise download the repository.
tmp=""
cleanup() { [ -n "$tmp" ] && rm -rf "$tmp"; return 0; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

script_dir=""
if [ -f "$0" ] && [ -d "$(dirname "$0")/skills" ]; then
  script_dir="$(cd "$(dirname "$0")" && pwd)"
fi

if [ -n "$script_dir" ] && [ -f "$script_dir/skills/security-scan/SKILL.md" ]; then
  source_root="$script_dir"
else
  command -v tar >/dev/null 2>&1 || die "tar is required to unpack the skills"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/security-skills.XXXXXX")"
  if [ -n "${SECURITY_SKILLS_ARCHIVE:-}" ]; then
    # Local tarball (offline installs and testing); same layout as the GitHub archive.
    cp "$SECURITY_SKILLS_ARCHIVE" "$tmp/src.tar.gz"
  else
    command -v curl >/dev/null 2>&1 || die "curl is required to download the skills"
    info "Downloading $REPO@$REF ..."
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF" -o "$tmp/src.tar.gz" \
      || curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" -o "$tmp/src.tar.gz" \
      || die "could not download $REPO at $REF"
  fi
  tar -xzf "$tmp/src.tar.gz" -C "$tmp"
  source_root="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -d "$source_root/skills" ] || die "download did not contain a skills/ directory"
fi

# Every directory under skills/ that has a SKILL.md is an installable skill.
available=""
for dir in "$source_root"/skills/*/; do
  [ -f "$dir/SKILL.md" ] || continue
  available="$available $(basename "$dir")"
done
available="${available# }"
[ -n "$available" ] || die "no skills found in $source_root/skills"

if [ "$list_only" -eq 1 ]; then
  for name in $available; do
    desc="$(sed -n 's/^description: *//p' "$source_root/skills/$name/SKILL.md" | head -n 1)"
    printf '%-26s %s\n' "$name" "$desc"
  done
  exit 0
fi

# --- prompt helpers ----------------------------------------------------------
have_tty=0
# Access checks are not enough: /dev/tty can exist yet fail to open (no
# controlling terminal, cron, CI). Only a successful open counts.
if { : </dev/tty; } 2>/dev/null; then have_tty=1; fi

ask() {
  # ask PROMPT DEFAULT -> sets $answer
  if [ "$have_tty" -eq 1 ]; then
    printf '%s [%s]: ' "$1" "$2" > /dev/tty
    IFS= read -r answer < /dev/tty || answer=""
  else
    answer=""
  fi
  [ -n "$answer" ] || answer="$2"
}

# --- choose skills -----------------------------------------------------------
selected=""
if [ -n "$skills_arg" ]; then
  if [ "$skills_arg" = "all" ]; then
    selected="$available"
  else
    selected="$(printf '%s' "$skills_arg" | tr ',' ' ')"
  fi
elif [ "$assume_yes" -eq 1 ] || [ "$have_tty" -eq 0 ]; then
  selected="$available"
else
  info ""
  info "Available skills:"
  i=1
  for name in $available; do
    printf '  %2d) %s\n' "$i" "$name" > /dev/tty
    i=$((i + 1))
  done
  info ""
  ask "Install which skills? Numbers or names, comma-separated, or 'all'" "all"
  if [ "$answer" = "all" ]; then
    selected="$available"
  else
    selected=""
    for item in $(printf '%s' "$answer" | tr ',' ' '); do
      case "$item" in
        *[!0-9]*) selected="$selected $item" ;;
        *)
          picked="$(printf '%s\n' $available | sed -n "${item}p")"
          [ -n "$picked" ] || die "no skill number $item"
          selected="$selected $picked" ;;
      esac
    done
  fi
fi

# Validate every requested name against the available list.
final=""
for name in $selected; do
  case " $available " in
    *" $name "*) final="$final $name" ;;
    *) die "unknown skill: $name (run with --list)" ;;
  esac
done
final="${final# }"
[ -n "$final" ] || die "no skills selected"

# --- choose destination ------------------------------------------------------
home_agents="$HOME/.agents/skills"
home_claude="$HOME/.claude/skills"
if [ -n "$dest_arg" ]; then
  dest="$dest_arg"
elif [ "$assume_yes" -eq 1 ] || [ "$have_tty" -eq 0 ]; then
  dest="$home_agents"
else
  info ""
  info "Where should they go?"
  info "  1) $home_agents    (Codex, Cursor, OpenCode, Zed, and other Agent Skills harnesses)"
  info "  2) $home_claude    (Claude Code)"
  info "  3) ./.agents/skills   (this project only)"
  info "  4) ./.claude/skills   (this project only, Claude Code)"
  info "  5) a path you type"
  ask "Choose 1-5" "1"
  case "$answer" in
    1) dest="$home_agents" ;;
    2) dest="$home_claude" ;;
    3) dest="$PWD/.agents/skills" ;;
    4) dest="$PWD/.claude/skills" ;;
    5) ask "Path" "$home_agents"; dest="$answer" ;;
    *) die "invalid choice: $answer" ;;
  esac
fi
case "$dest" in
  "~") dest="$HOME" ;;
  "~/"*) dest="$HOME/${dest#\~/}" ;;
esac

# --- install -----------------------------------------------------------------
info ""
info "Installing to $dest:"
installed=0
skipped=0
for name in $final; do
  src="$source_root/skills/$name"
  target="$dest/$name"
  if [ -e "$target" ] && [ ! -f "$target/$MARKER" ] && [ "$force" -eq 0 ]; then
    info "  skip   $name (exists and was not installed by this script; use --force to replace)"
    skipped=$((skipped + 1))
    continue
  fi
  if [ "$dry_run" -eq 1 ]; then
    info "  would install $name -> $target"
    continue
  fi
  mkdir -p "$dest"
  status="ok    "
  [ -e "$target" ] && status="update"
  rm -rf "$target"
  cp -R "$src" "$target"
  printf 'antstanley/security-skills\n' > "$target/$MARKER"
  info "  $status $name"
  installed=$((installed + 1))
done

info ""
if [ "$dry_run" -eq 1 ]; then
  info "Dry run: nothing was changed."
else
  info "Installed $installed skill(s)$( [ "$skipped" -gt 0 ] && printf ', skipped %s' "$skipped")."
  info "Restart your agent or start a new session so it picks up the skills."
fi
