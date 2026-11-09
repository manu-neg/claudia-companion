#!/usr/bin/env bash
# deploy/setup-wizard.sh — interactive front end for deploy/install.sh.
#
# Asks for the owner's Tailscale login, the tailnet host and the uv path
# (defaults detected from `tailscale status --json` and PATH), validates
# them, prints the exact install.sh command and then runs it. Never asks
# for, reads or writes a secret (tokens and the TOTP secret are later,
# separate steps: docs/setup.md). --dry-run is passed through to install.sh.
#
# Usage:
#   sudo deploy/setup-wizard.sh
#   deploy/setup-wizard.sh --dry-run            # no root needed, changes nothing
#   deploy/setup-wizard.sh --dry-run --no-detect   # no tailscale/PATH probing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"

DRY_RUN=0
DETECT=1
EXTRA=()

usage() {
    cat <<'EOF'
usage: setup-wizard.sh [--dry-run] [--no-detect] [-- INSTALL_OPTIONS...]

  --dry-run     Pass --dry-run to install.sh (prints every action, no root)
  --no-detect   Don't probe tailscale/PATH for defaults
  -- ...        Further install.sh options, passed through unchanged and
                validated by install.sh (e.g. --telegram-chat-id ID
                --telegram-token-file PATH --claudia)
  -h, --help    Show this help

Asks for: owner login, tailnet host, uv path. Then runs
deploy/install.sh --owner-login ... --host ... --uv-bin ... [INSTALL_OPTIONS] [--dry-run]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --no-detect)
            DETECT=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            EXTRA=("$@")
            break
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# These come only from the prompts/wizard flags: a passthrough copy would be
# ambiguous (install.sh keeps the last one).
for _arg in "${EXTRA[@]}"; do
    case "$_arg" in
        --owner-login | --host | --uv-bin | --dry-run)
            echo "error: pass $_arg via the prompts/wizard flags, not after --" >&2
            exit 2
            ;;
    esac
done

# Fail before any prompt: a real install needs root anyway.
if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (or pass --dry-run)" >&2
    exit 1
fi
if [[ ! -f "$INSTALL_SH" ]]; then
    echo "error: $INSTALL_SH not found" >&2
    exit 1
fi

# --- defaults (best effort; any failure just means "no default") ---------------
DEFAULT_LOGIN=""
DEFAULT_HOST=""
DEFAULT_UV=""

detect_tailscale() {
    # Prints this node's login and host (one per line), or nothing. JSON is parsed by
    # python3 in isolated mode (-I) so nothing from the cwd is imported.
    command -v tailscale >/dev/null 2>&1 || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    tailscale status --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    data = json.load(sys.stdin)
    me = data.get("Self") or {}
    user = (data.get("User") or {}).get(str(me.get("UserID")), {})
    print(user.get("LoginName", ""))
    print(str(me.get("DNSName", "")).rstrip("."))
except Exception:
    pass
' 2>/dev/null || true
}

if [[ "$DETECT" -eq 1 ]]; then
    _ts="$(detect_tailscale)"
    DEFAULT_LOGIN="$(printf '%s\n' "$_ts" | sed -n 1p)"
    DEFAULT_HOST="$(printf '%s\n' "$_ts" | sed -n 2p)"
    DEFAULT_UV="$(command -v uv 2>/dev/null || true)"
    if [[ -z "$DEFAULT_UV" && -x /root/.local/bin/uv ]]; then
        DEFAULT_UV="/root/.local/bin/uv"
    fi
fi

# --- validation (same shapes install.sh/config.py accept, stricter where cheap) --
valid_login() {
    # Tailscale login names: user@domain or user@github (no spaces/controls).
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]
}

valid_host() {
    # A tailnet MagicDNS name: lowercase labels ending in .ts.net.
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.ts\.net$ ]]
}

valid_uv() {
    # Absolute, executable, and only characters that can't split or expand.
    [[ "$1" =~ ^/[A-Za-z0-9._/+-]+$ && -x "$1" && ! -d "$1" ]]
}

# ask VAR "Prompt" DEFAULT VALIDATOR "hint": re-asks up to 3 times, then fails.
ask() {
    local __var="$1" prompt="$2" default="$3" check="$4" hint="$5" answer tries=0
    while [[ $tries -lt 3 ]]; do
        tries=$((tries + 1))
        if [[ -n "$default" ]]; then
            printf '%s [%s]: ' "$prompt" "$default" >&2
        else
            printf '%s: ' "$prompt" >&2
        fi
        if ! IFS= read -r answer; then
            echo >&2
            echo "error: no answer (end of input)" >&2
            exit 2
        fi
        answer="${answer:-$default}"
        if "$check" "$answer"; then
            printf -v "$__var" '%s' "$answer"
            return 0
        fi
        echo "  invalid: $hint" >&2
    done
    echo "error: too many invalid answers" >&2
    exit 2
}

echo "Preview dashboard setup (docs/setup.md). Nothing secret is asked here." >&2
echo "Only the login you give first may open the dashboard; use the same one as" >&2
echo "OWNER_LOGIN in deploy/tailscale/acl-snippet.json." >&2
# The same login goes into the ACL snippet as OWNER_LOGIN; the default is the
# login this host was enrolled with, which may not be the one you browse with.
ask OWNER_LOGIN "Tailscale login you will open the dashboard with (e.g. you@example.com)" \
    "$DEFAULT_LOGIN" \
    valid_login "an email-style login like you@example.com or you@github"
ask HOST "Tailnet host name (e.g. dashboard.tailnet-name.ts.net)" "$DEFAULT_HOST" \
    valid_host "a lowercase MagicDNS name ending in .ts.net"
ask UV_PATH "Path to uv" "$DEFAULT_UV" \
    valid_uv "an absolute path to the uv executable"

CMD=("$INSTALL_SH" --owner-login "$OWNER_LOGIN" --host "$HOST" --uv-bin "$UV_PATH")
CMD+=("${EXTRA[@]}")
if [[ "$DRY_RUN" -eq 1 ]]; then
    CMD+=(--dry-run)
fi

echo "Will run:" >&2
printf ' %q' "${CMD[@]}" >&2
echo >&2

if [[ "$DRY_RUN" -eq 0 ]]; then
    printf 'Proceed? [y/N]: ' >&2
    IFS= read -r confirm || confirm=""
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "cancelled; nothing changed" >&2
        exit 1
    fi
fi

exec "${BASH:-bash}" "${CMD[@]}"
