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
    --skills)  [ $# -ge 2 ] && [ -n "$2" ] || die "--skills needs a non-empty value"
               skills_arg="$2"; shift 2 ;;
    --dest)    [ $# -ge 2 ] && [ -n "$2" ] || die "--dest needs a non-empty value"
               dest_arg="$2"; shift 2 ;;
    --ref)     [ $# -ge 2 ] && [ -n "$2" ] || die "--ref needs a non-empty value"
               REF="$2"; shift 2 ;;
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
stage=""
stage_target=""
cleanup() {
  [ -n "$tmp" ] && rm -rf "$tmp"
  if [ -n "$stage" ]; then
    # Interrupted between moving the old folder aside and moving the new one in:
    # put the old folder back rather than lose it.
    if [ -e "$stage/previous" ] && [ ! -e "$stage_target" ] && [ ! -L "$stage_target" ]; then
      mv "$stage/previous" "$stage_target" 2>/dev/null || true
    fi
    rm -rf "$stage"
  fi
  return 0
}
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

# Nothing below needs pathname expansion, and every unquoted list ($available,
# $selected, $final, typed answers) is split on whitespace. Turn globbing off so
# a value such as "*" is checked as a name instead of matching files in $PWD.
set -f

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
# Probe in a subshell: ":" is a special builtin, so in dash a failed
# redirection on it would exit the whole script instead of the test.
if ( : </dev/tty ) 2>/dev/null; then have_tty=1; fi

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
[ -n "$dest" ] || die "the destination must not be empty"

# real_path PATH -> absolute path with symlinks resolved, even if PATH does not
# exist yet (the missing tail is appended to its nearest existing ancestor).
real_path() {
  rp_path="$1"
  rp_tail=""
  case "$rp_path" in /*) ;; *) rp_path="$PWD/$rp_path" ;; esac
  while [ ! -d "$rp_path" ]; do
    rp_base="$(basename "$rp_path")"
    case "$rp_base" in
      .|..) die "cannot resolve $1: '.' or '..' after a directory that does not exist" ;;
    esac
    rp_tail="/$rp_base$rp_tail"
    rp_path="$(dirname "$rp_path")"
  done
  rp_path="$(cd "$rp_path" && pwd -P)" || die "cannot resolve $1"
  printf '%s%s\n' "${rp_path%/}" "$rp_tail"
}

# overlaps A B -> true when A and B are the same path or one contains the other.
overlaps() {
  case "$1/" in "$2/"*) return 0 ;; esac
  case "$2/" in "$1/"*) return 0 ;; esac
  return 1
}

source_skills="$(real_path "$source_root/skills")"

# --- install -----------------------------------------------------------------
info ""
info "Installing to $dest:"
installed=0
skipped=0
for name in $final; do
  src="$source_root/skills/$name"
  target="$dest/$name"
  # Never install over, into, or around the folders being copied: replacing the
  # target would delete the source (for example --dest pointing at this checkout).
  target_real="$(real_path "$target")"
  target_link="$(real_path "$dest")/$name"
  if overlaps "$target_real" "$source_skills" || overlaps "$target_link" "$source_skills"; then
    die "refusing to install $name into $target: it overlaps the source $source_skills"
  fi
  if { [ -e "$target" ] || [ -L "$target" ]; } && [ ! -f "$target/$MARKER" ] \
    && [ "$force" -eq 0 ]; then
    info "  skip   $name (exists and was not installed by this script; use --force to replace)"
    skipped=$((skipped + 1))
    continue
  fi
  if [ "$dry_run" -eq 1 ]; then
    info "  would install $name -> $target"
    continue
  fi
  mkdir -p "$dest"
  # Copy into a staging folder beside the target, then swap it in, so a failed
  # copy never leaves a half-installed skill or removes the working one.
  stage="$(mktemp -d "$dest/.security-skills-stage.XXXXXX")"
  stage_target="$target"
  cp -R "$src" "$stage/new"
  printf 'antstanley/security-skills\n' > "$stage/new/$MARKER"
  status="ok    "
  if [ -e "$target" ] || [ -L "$target" ]; then
    status="update"
    mv "$target" "$stage/previous"
  fi
  if ! mv "$stage/new" "$target"; then
    [ -e "$stage/previous" ] && mv "$stage/previous" "$target"
    die "could not move $name into place; the previous version was kept"
  fi
  rm -rf "$stage"
  stage=""
  stage_target=""
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
