#!/usr/bin/env bash
# deploy/install.sh — install/update the preview-dashboard services.
#
# Idempotent: safe to re-run after a `git pull` (updates the code + venv in
# place, leaves existing users/data/tokens/config untouched -- except that
# --telegram-chat-id adds the two notifier keys to config.toml if absent).
# Requires root unless --dry-run, which only prints every action it would
# take (works as any user — used by tests/unit/test_deploy_artifacts.py).
#
# Usage:
#   sudo deploy/install.sh --owner-login OWNER_LOGIN --host HOST.ts.net
#   deploy/install.sh --dry-run --owner-login owner@example.com --host x.ts.net
#
# What this does NOT do (owner/operator actions, see docs/operations.md):
#   - `tailscale up` (enroll this host in the tailnet)
#   - `tailscale serve` / the tailnet ACL (deploy/tailscale/)
#   - install Tailscale itself, or any package (the notifier needs `acl`)
#   - Claudia (--claudia): `claude login` as root, the TOTP secret
#     (`claudia totp setup`), downloading voice models, or turning
#     `claudia_enabled` on -- install.sh only reads that flag (ADR 0036)
set -euo pipefail

# --- constants ---------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(cd "$SCRIPT_DIR/.." && pwd)"
# The one shared group. Named "pdash" (ADR 0013's original name, restored by
# ADR 0017 amendment "G"): interfaces/mcp/server.py no longer hardcodes any
# group name — it trusts whatever gid actually owns the admin socket, read
# straight off the socket itself (verify_admin_socket, unit 10b M1/G). The
# service *users* stay "pdash-admin"/"pdash-viewer".
SERVICE_GROUP="pdash"
ADMIN_USER="pdash-admin"
VIEWER_USER="pdash-viewer"
# Notifier (N5, docs/security.md C33): its own user/primary group, never a
# member of "pdash" (must never read admin.token or touch db/blobs/). The
# only extra grant is a shared group for notifier.token, held by pdash-admin
# (which verifies it, C12) and pdash-notify (which presents it, C36).
NOTIFY_USER="pdash-notify"
NOTIFY_TOK_GROUP="pdash-notifytok"
# Claudia (M9, ADR 0036; docs/security.md C45/C47/C57): one group per file,
# like the notifier's. pdash-claudiatok = claudia.token (host presents,
# admin verifies); pdash-totp = totp.secret (admin only, never "pdash",
# S-C1 S2); pdash-kb = the knowledge base's read group, held only by the
# viewer unit (SupplementaryGroups=) -- created on EVERY host, so that
# static unit starts whether or not Claudia is installed.
CLAUDIA_TOK_GROUP="pdash-claudiatok"
TOTP_GROUP="pdash-totp"
KB_GROUP="pdash-kb"
TOKEN_FILE_MODE=0640
CONFIG_FILE_MODE=0644

# --- args ----------------------------------------------------------------------
DRY_RUN=0
OWNER_LOGIN=""
HOST=""
REPO_ROOT="$REPO_ROOT_DEFAULT"
UV_BIN="${PDASH_UV_BIN:-uv}"
PREFIX="${PDASH_PREFIX:-}"   # advanced/test use only: prefixes filesystem paths
# Test hooks only (like PDASH_UV_BIN): which setfacl/python3 the preflight uses.
SETFACL_BIN="${PDASH_SETFACL_BIN:-setfacl}"
PYTHON_BIN="${PDASH_PYTHON_BIN:-python3}"
# Test hook only, refused without --dry-run (below): which id/getent decide
# user/group existence (id_exists, group_exists). Without this, --dry-run tests read *this host's*
# real accounts (e.g. a live-deployed pdash-notify), making output
# nondeterministic (G3, backlog.md).
ID_BIN="${PDASH_ID_BIN:-id}"
GETENT_BIN="${PDASH_GETENT_BIN:-getent}"
# Test hook only, refused without --dry-run: the cgroup file the "not from
# inside claudia-host" preflight reads (deploy-4).
CGROUP_FILE="${PDASH_CGROUP_FILE:-/proc/self/cgroup}"
TELEGRAM_CHAT_ID=""          # empty = notifier not installed (default, unchanged behavior)
TELEGRAM_TOKEN_FILE=""
CLAUDIA_FLAG=0               # 0 = Claudia not installed (default, unchanged behavior)
CLAUDE_BIN="/root/.local/bin/claude"
VOICE_MODELS=""              # empty = no voice replies (no extra, no models)

usage() {
    cat <<'EOF'
usage: install.sh --owner-login LOGIN --host HOST.ts.net [options]

Required:
  --owner-login LOGIN   The owner's Tailscale login (config.toml owner_login, C2)
  --host HOST           The tailnet hostname from `tailscale serve status`
                         (fills allowed_hosts / preview_origin)

Options:
  --dry-run             Print every action instead of taking it; no root needed
  --repo PATH            Source tree to install from (default: this script's repo)
  --uv-bin PATH           uv executable to use (default: $PDASH_UV_BIN or "uv")
  --telegram-chat-id ID   Enable the Telegram notifier: owner's chat id (from
                          `preview-dashboard notify pair`, run after this
                          installs). Written to config.toml (added to an
                          existing file if absent; a different id already
                          there is refused). Needs `setfacl` (apt install acl).
                          Once installed, the notifier stays installed and
                          configured on re-runs without this flag (host state
                          decides; docs/security.md C33/C38, ADR 0023).
  --telegram-token-file PATH   Copy this file in as the Telegram bot token
                          (root:pdash-notify 0640, C36); never echoed. If
                          omitted, place /etc/preview-dashboard/telegram.token
                          by hand before starting preview-dashboard-notifier.
  --claudia               Install the Claudia companion (needs the notifier):
                          groups, claudia.token, host settings + MCP config,
                          KB/state dirs, claudia-host + weekly gardener units.
                          Enabled only if config.toml already has
                          claudia_enabled = true and totp.secret exists; this
                          script never turns it on. Stays installed on
                          re-runs without the flag (host state decides).
  --claude-bin PATH       The root `claude` CLI the host and gardener run
                          (default /root/.local/bin/claude; absolute)
  --voice-models DIR      Voice replies: copy the two Piper voices from DIR,
                          then check the copies against the hashes pinned in
                          deploy/claudia/voices.sha256 (refused while not
                          pinned; re-checked on every run) and add the
                          claudia-voice extra. Without it no voice is
                          installed (nothing is downloaded)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --owner-login)
            OWNER_LOGIN="${2:?--owner-login needs a value}"
            shift 2
            ;;
        --host)
            HOST="${2:?--host needs a value}"
            shift 2
            ;;
        --repo)
            REPO_ROOT="${2:?--repo needs a value}"
            shift 2
            ;;
        --uv-bin)
            UV_BIN="${2:?--uv-bin needs a value}"
            shift 2
            ;;
        --telegram-chat-id)
            TELEGRAM_CHAT_ID="${2:?--telegram-chat-id needs a value}"
            shift 2
            ;;
        --telegram-token-file)
            TELEGRAM_TOKEN_FILE="${2:?--telegram-token-file needs a value}"
            shift 2
            ;;
        --claudia)
            CLAUDIA_FLAG=1
            shift
            ;;
        --claude-bin)
            CLAUDE_BIN="${2:?--claude-bin needs a value}"
            shift 2
            ;;
        --voice-models)
            VOICE_MODELS="${2:?--voice-models needs a value}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$OWNER_LOGIN" || -z "$HOST" ]]; then
    echo "error: --owner-login and --host are required" >&2
    usage >&2
    exit 2
fi

# No leading zero: the value is written into config.toml as a TOML integer.
if [[ -n "$TELEGRAM_CHAT_ID" && ! "$TELEGRAM_CHAT_ID" =~ ^[1-9][0-9]{0,18}$ ]]; then
    echo "error: --telegram-chat-id must be a positive integer" >&2
    exit 2
fi
if [[ -n "$TELEGRAM_TOKEN_FILE" && -z "$TELEGRAM_CHAT_ID" ]]; then
    echo "error: --telegram-token-file needs --telegram-chat-id too" >&2
    exit 2
fi
# Lands unquoted in the units' ExecStart (claudia.env): absolute, and only
# characters that can't split or expand there.
if [[ ! "$CLAUDE_BIN" =~ ^/[A-Za-z0-9._/+-]+$ ]]; then
    echo "error: --claude-bin must be an absolute path of [A-Za-z0-9._/+-] characters" >&2
    exit 2
fi
if [[ -n "$VOICE_MODELS" && "$VOICE_MODELS" != /* ]]; then
    echo "error: --voice-models must be an absolute path" >&2
    exit 2
fi

# The id/getent hooks only make --dry-run output hermetic: a real install
# decides which accounts exist with the system tools, never a caller-chosen
# binary (a stub could make it skip creating a user or reuse a stranger's).
if [[ "$DRY_RUN" -eq 0 && ( -n "${PDASH_ID_BIN:-}" || -n "${PDASH_GETENT_BIN:-}" || -n "${PDASH_CGROUP_FILE:-}" ) ]]; then
    echo "error: PDASH_ID_BIN/PDASH_GETENT_BIN/PDASH_CGROUP_FILE are test hooks, only honoured with --dry-run" >&2
    exit 2
fi

# deploy-4: never from inside claudia-host.service. Restarting the admin
# (step 12) restarts the host too (Requires=), and KillMode=control-group
# would kill this script mid-run, silently skipping the unit checks and
# check.sh. Fail closed if the cgroup can't even be read.
if [[ ! -r "$CGROUP_FILE" ]]; then
    echo "error: cannot read $CGROUP_FILE to check where install.sh runs" >&2
    exit 1
fi
if grep -Eq '/claudia-host\.service(/|$)' "$CGROUP_FILE"; then
    echo "error: install.sh is running inside claudia-host.service; restarting the admin" >&2
    echo "       would kill it before its checks. Run it from the owner's terminal" >&2
    echo "       (or outside the host's cgroup, e.g. systemd-run --scope ...)." >&2
    exit 2
fi

if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (or pass --dry-run)" >&2
    exit 1
fi

# --- paths (PDASH_PREFIX only for test isolation; empty in production) --------
OPT_DIR="${PREFIX}/opt/preview-dashboard"
ETC_DIR="${PREFIX}/etc/preview-dashboard"
VAR_DIR="${PREFIX}/var/lib/preview-dashboard"
SYSTEMD_DIR="${PREFIX}/etc/systemd/system"
OUTBOX_DIR="${PREFIX}/root/outbox"
CONFIG_FILE="$ETC_DIR/config.toml"
TOKEN_FILE="$ETC_DIR/admin.token"
ADMIN_UID_ENV="$ETC_DIR/admin-uid.env"
VIEWER_UID_ENV="$ETC_DIR/viewer-uid.env"
NOTIFIER_TOKEN_FILE="$ETC_DIR/notifier.token"
TELEGRAM_TOKEN_DEST="$ETC_DIR/telegram.token"
NOTIFIER_ADMIN_ENV="$ETC_DIR/notifier-admin.env"
NOTIFIER_UNIT_DEST="$SYSTEMD_DIR/preview-dashboard-notifier.service"
NOTIFY_CONFIG_PY="$SCRIPT_DIR/lib/notify_config.py"
NOTIFY_EGRESS_TEMPLATE="$SCRIPT_DIR/nftables/notifier-egress.nft.in"
VENV_BIN="$OPT_DIR/.venv/bin"
PDASH_BIN="$VENV_BIN/preview-dashboard"
# Claudia (M9). The units name the unprefixed /etc and /var/lib paths.
KB_DIR="${PREFIX}/var/lib/claudia-kb"
HOST_STATE_DIR="${PREFIX}/var/lib/claudia-host"
VOICES_DIR="$HOST_STATE_DIR/voices"
VOICES_STAGING="$HOST_STATE_DIR/voices.incoming"  # root 0700: copies hashed here
CLAUDIA_TOKEN_FILE="$ETC_DIR/claudia.token"
TOTP_SECRET_FILE="$ETC_DIR/totp.secret"
CLAUDIA_SETTINGS_DEST="$ETC_DIR/claudia-settings.json"
CLAUDIA_MCP_DEST="$ETC_DIR/claudia-mcp.json"
CLAUDIA_ADMIN_ENV="$ETC_DIR/claudia-admin.env"
CLAUDIA_ENV="$ETC_DIR/claudia.env"
CLAUDIA_HOST_UNIT_DEST="$SYSTEMD_DIR/claudia-host.service"
CLAUDIA_SETTINGS_SRC="$SCRIPT_DIR/claudia/settings.json"
CLAUDIA_MCP_TEMPLATE="$SCRIPT_DIR/claudia/mcp.json.in"
VOICE_PINS="$SCRIPT_DIR/claudia/voices.sha256"
VOICE_FILES=(es_MX-claude-high.onnx es_MX-claude-high.onnx.json
    en_US-amy-medium.onnx en_US-amy-medium.onnx.json)
# The C59 hook command (console script from unit M5a); the host settings
# file names exactly this path.
HOOK_BIN="$VENV_BIN/preview-dashboard-claudia-hook"

# --- helpers -------------------------------------------------------------------
log() { echo "== $*"; }

run() {
    echo "+ $*"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        "$@"
    fi
}

# install(1)-style file write: prints the action in dry-run, writes for real
# otherwise. $1=content (via stdin), $2=dest, $3=mode, $4=owner:group.
write_file() {
    local dest="$1" mode="$2" owner="$3"
    echo "+ write $dest (mode $mode, owner $owner)"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        cat >"$dest"
        chmod "$mode" "$dest"
        chown "$owner" "$dest"
    else
        cat >/dev/null
    fi
}

id_exists() { "$ID_BIN" -u "$1" >/dev/null 2>&1; }
group_exists() { "$GETENT_BIN" group "$1" >/dev/null 2>&1; }

ensure_group() {
    if group_exists "$1"; then
        echo "  group $1 already exists"
    else
        run groupadd --system "$1"
    fi
}

# Idempotent supplementary-group grant ($1 group, $2 user).
ensure_member() {
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if ! id -nG "$2" | tr ' ' '\n' | grep -qx "$1"; then
            run usermod -aG "$1" "$2"
        else
            echo "  $2 already in $1"
        fi
    else
        echo "+ usermod -aG $1 $2   (if not already a member)"
    fi
}

# "<64 hex>  <name>" lines of the voice pin file (comments dropped).
voice_pins() { grep -E '^[0-9a-f]{64}  [A-Za-z0-9._-]+$' "$VOICE_PINS" || true; }

# 0 iff all four voice files in dir $1 match their pins (every one must be
# pinned; names have no "/", so the check stays inside $1).
verify_voices() {
    local dir="$1" pins f
    pins="$(voice_pins)"
    for f in "${VOICE_FILES[@]}"; do
        if ! grep -q "  ${f}\$" <<<"$pins"; then
            echo "error: $f is not pinned in $VOICE_PINS" >&2
            return 1
        fi
    done
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "+ sha256sum --check --strict (pinned hashes) in $dir"
        return 0
    fi
    env -C "$dir" sha256sum --check --strict --quiet - <<<"$pins"
}

# Every member of group $1, one per line: its member list plus every user
# whose PRIMARY group it is (getent's member field omits those). Prints
# nothing for a missing group; a failed passwd lookup fails the caller.
group_members() {
    local line gid
    line="$("$GETENT_BIN" group "$1")" || return 0
    gid="$(cut -d: -f3 <<<"$line")"
    cut -d: -f4 <<<"$line" | tr ',' '\n' | sed '/^$/d'
    "$GETENT_BIN" passwd | awk -F: -v g="$gid" '$4 == g { print $1 }'
}

# deploy-5: a pre-existing group is reused only if it holds no one but the
# allowed users ($2...): an extra member of pdash-claudiatok would read
# claudia.token, of pdash-totp the TOTP secret, of pdash-kb the KB. Never
# "fixed" here (removing someone from a group is the owner's call).
refuse_unexpected_members() {
    local group="$1" members m allowed ok
    shift
    members="$(group_members "$group")"
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        ok=0
        for allowed in "$@"; do
            if [[ "$m" == "$allowed" ]]; then
                ok=1
            fi
        done
        if [[ "$ok" -eq 0 ]]; then
            echo "error: group $group already exists with unexpected member '$m'" >&2
            echo "       (allowed: ${*:-none}); remove it first (owner action), then re-run" >&2
            exit 2
        fi
    done <<<"$members"
}

# deploy-1: a directory INSIDE the data dir ($VAR_DIR is pdash-admin's, so a
# compromised admin can plant a symlink there). Root never runs install -d /
# chown / chmod on such a path (an existing-dir install -d follows symlinks
# and would hand the target to pdash-admin): pdash-admin creates and fixes
# it itself, then a no-follow stat must show exactly the expected directory.
# $1=path, $2=mode (0700/0750); owner pdash-admin, group pdash.
ensure_admin_dir() {
    local dir="$1" mode="$2" got want
    if [[ -L "$dir" ]] || [[ -e "$dir" && ! -d "$dir" ]]; then
        echo "error: $dir is a symlink or not a directory; refusing (inspect it by hand)" >&2
        exit 1
    fi
    if [[ ! -e "$dir" ]]; then
        run runuser -u "$ADMIN_USER" -- mkdir -m "$mode" -- "$dir"
    fi
    run runuser -u "$ADMIN_USER" -- chgrp -- "$SERVICE_GROUP" "$dir"
    run runuser -u "$ADMIN_USER" -- chmod -- "$mode" "$dir"
    want="directory $ADMIN_USER:$SERVICE_GROUP ${mode#0}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "+ stat -c '%F %U:%G %a' $dir   (must be: $want)"
        return
    fi
    got="$(stat -c '%F %U:%G %a' -- "$dir")"
    if [[ "$got" != "$want" ]]; then
        echo "error: $dir is '$got', expected '$want'; refusing" >&2
        exit 1
    fi
}

# --- 0. notifier state + preflight (before ANY change) -------------------------
# M2 (S-B): "notifier installed" is host state (its unit file or its user),
# not this run's flags -- a plain re-run after `git pull` must keep the nft
# egress block, the admin env file and the token-group args, or the admin
# would silently stop accepting the notifier (or the table would lose C38).
NOTIFIER=0
if [[ -n "$TELEGRAM_CHAT_ID" || -e "$NOTIFIER_UNIT_DEST" ]] || id_exists "$NOTIFY_USER"; then
    NOTIFIER=1
fi
if [[ "$NOTIFIER" -eq 1 ]]; then
    # M3 (S-B): the admin unit reaches pdash-notify only through setfacl
    # (ADR 0023). Refuse up front instead of installing a notifier that
    # can never connect; installing packages stays an owner decision.
    if ! command -v "$SETFACL_BIN" >/dev/null 2>&1; then
        echo "error: the Telegram notifier needs setfacl (package 'acl'), which is not installed." >&2
        echo "       Install it first (owner action): apt install acl -- then re-run install.sh." >&2
        exit 1
    fi
    # A chat id conflict must stop us before anything is touched (C34).
    if [[ -n "$TELEGRAM_CHAT_ID" && -e "$CONFIG_FILE" ]]; then
        if ! "$PYTHON_BIN" "$NOTIFY_CONFIG_PY" check "$CONFIG_FILE" "$TELEGRAM_CHAT_ID"; then
            echo "error: $CONFIG_FILE can't take --telegram-chat-id $TELEGRAM_CHAT_ID (see above)" >&2
            exit 2
        fi
    fi
fi

# --- 0b. Claudia state + preflight (before ANY change; M9, ADR 0036) -----------
# Host state decides, as for the notifier: once claudia-host.service is
# installed a plain re-run keeps every Claudia piece (env files, groups).
CLAUDIA=0
if [[ "$CLAUDIA_FLAG" -eq 1 || -e "$CLAUDIA_HOST_UNIT_DEST" ]]; then
    CLAUDIA=1
fi
if [[ "$CLAUDIA" -eq 1 && "$NOTIFIER" -eq 0 ]]; then
    # Owner messages, taps and codes only arrive through the notifier (C44).
    echo "error: Claudia needs the Telegram notifier: pass --telegram-chat-id too" >&2
    exit 2
fi
if [[ -n "$VOICE_MODELS" && "$CLAUDIA" -eq 0 ]]; then
    echo "error: --voice-models needs --claudia" >&2
    exit 2
fi
# Voice stays installed once its models are in place (else `uv sync` would
# drop the extra on a plain re-run).
VOICE=0
if [[ "$CLAUDIA" -eq 1 ]] && [[ -n "$VOICE_MODELS" || -d "$VOICES_DIR" ]]; then
    VOICE=1
fi
if [[ -n "$VOICE_MODELS" ]]; then
    # Fail closed: every voice file must be pinned in the repo before any
    # model is trusted; install.sh itself never downloads anything.
    _pins="$(voice_pins)"
    for f in "${VOICE_FILES[@]}"; do
        if ! grep -q "  ${f}\$" <<<"$_pins"; then
            echo "error: $f is not pinned in $VOICE_PINS (add its SHA-256 first)" >&2
            exit 2
        fi
        if [[ ! -f "$VOICE_MODELS/$f" ]]; then
            echo "error: $VOICE_MODELS/$f is missing" >&2
            exit 2
        fi
    done
fi
if [[ "$CLAUDIA" -eq 1 && "$DRY_RUN" -eq 0 && ! -x "$CLAUDE_BIN" ]]; then
    echo "error: no executable claude CLI at $CLAUDE_BIN (install it and run \`claude\`" >&2
    echo "       as root to log in with the subscription, or pass --claude-bin)" >&2
    exit 1
fi
# deploy-5: vet reused groups before anything changes. pdash-kb has no
# members at all (only the viewer unit holds it, SupplementaryGroups=).
refuse_unexpected_members "$KB_GROUP"
if [[ "$CLAUDIA" -eq 1 ]]; then
    refuse_unexpected_members "$CLAUDIA_TOK_GROUP" "$ADMIN_USER"
    refuse_unexpected_members "$TOTP_GROUP" "$ADMIN_USER"
fi

# --- 1. group + users (system, nologin, no home; docs/security.md C28) --------
log "group and users"
if group_exists "$SERVICE_GROUP"; then
    echo "  group $SERVICE_GROUP already exists"
else
    run groupadd --system "$SERVICE_GROUP"
fi

for user in "$ADMIN_USER" "$VIEWER_USER"; do
    if id_exists "$user"; then
        echo "  user $user already exists"
    else
        # -N: don't create a same-named private group (primary group is
        # $SERVICE_GROUP, "pdash", instead) — both services share one
        # primary group so files each one creates land group-`pdash`
        # without needing setgid everywhere; interfaces/mcp/server.py reads
        # that group straight off the admin socket at runtime, so it never
        # needs to match a hardcoded name (ADR 0013, ADR 0017 "G"). -M: no
        # home directory. -s nologin: no shell.
        run useradd --system --no-create-home --no-user-group \
            --gid "$SERVICE_GROUP" --shell /usr/sbin/nologin \
            --home-dir /nonexistent \
            --comment "preview-dashboard service account" "$user"
    fi
done
# No members: only the viewer unit holds it (SupplementaryGroups=), and it
# must exist for that unit to start at all (constants above).
ensure_group "$KB_GROUP"

# --- 1b. notifier user + shared token group (notifier installed, step 0;
# always idempotent: existing accounts are only reported) --------------------
if [[ "$NOTIFIER" -eq 1 ]]; then
    log "notifier group and user"
    if group_exists "$NOTIFY_TOK_GROUP"; then
        echo "  group $NOTIFY_TOK_GROUP already exists"
    else
        run groupadd --system "$NOTIFY_TOK_GROUP"
    fi
    if id_exists "$NOTIFY_USER"; then
        echo "  user $NOTIFY_USER already exists"
    else
        # --user-group (opposite of admin/viewer, deliberately): pdash-notify
        # gets its OWN private primary group, never "pdash" (C33 -- it must
        # never gain read access to admin.token or db/blobs/ via that group).
        # -G: also a member of pdash-notifytok (notifier.token only, C36).
        run useradd --system --no-create-home --user-group \
            --shell /usr/sbin/nologin --home-dir /nonexistent \
            -G "$NOTIFY_TOK_GROUP" \
            --comment "preview-dashboard notifier service account" "$NOTIFY_USER"
    fi
    # Idempotent supplementary-group grant for pdash-admin (needs to read
    # notifier.token itself when validating it, C12/C36); safe to re-check
    # on every run, incl. one where pdash-admin already existed before N5.
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if ! id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx "$NOTIFY_TOK_GROUP"; then
            run usermod -aG "$NOTIFY_TOK_GROUP" "$ADMIN_USER"
        else
            echo "  $ADMIN_USER already in $NOTIFY_TOK_GROUP"
        fi
    else
        echo "+ usermod -aG $NOTIFY_TOK_GROUP $ADMIN_USER   (if not already a member)"
    fi
fi

# --- 1c. Claudia token + TOTP groups (Claudia installed, step 0b) -----------------
# pdash-admin is the ONLY member of either: it verifies claudia.token and is
# the only reader of totp.secret (C45, C47 / S-C1 S2). The host gets
# pdash-claudiatok as its unit Group= instead of a membership.
if [[ "$CLAUDIA" -eq 1 ]]; then
    log "Claudia groups"
    ensure_group "$CLAUDIA_TOK_GROUP"
    ensure_group "$TOTP_GROUP"
    ensure_member "$CLAUDIA_TOK_GROUP" "$ADMIN_USER"
    ensure_member "$TOTP_GROUP" "$ADMIN_USER"
fi

# --- 2. resolve pdash-admin's uid for the viewer unit's --trusted-owner-uid,
#        and pdash-viewer's for admin/purge/migrate --trusted-sidecar-uid ------
# The viewer writes the DB too and recreates -wal/-shm (as itself) whenever
# it opens the DB while no admin connection is open (ADR 0025).
log "admin uid -> $ADMIN_UID_ENV, viewer uid -> $VIEWER_UID_ENV"
if [[ "$DRY_RUN" -eq 0 ]]; then
    ADMIN_UID="$(id -u "$ADMIN_USER")"
    VIEWER_UID="$(id -u "$VIEWER_USER")"
else
    ADMIN_UID="<resolved-at-install-time>"
    VIEWER_UID="<resolved-at-install-time>"
fi
run install -d -m 0755 -o root -g root "$ETC_DIR"  # must exist before the writes below
printf 'PDASH_ADMIN_UID=%s\n' "$ADMIN_UID" | write_file "$ADMIN_UID_ENV" 0644 root:root
printf 'PDASH_VIEWER_UID=%s\n' "$VIEWER_UID" | write_file "$VIEWER_UID_ENV" 0644 root:root

# --- 3. directories --------------------------------------------------------------
log "directories"
run install -d -m 0755 -o root -g root "$OPT_DIR"
run install -d -m 0755 -o root -g root "$ETC_DIR"
# NOT 2770: FsBlobStore refuses a group-writable root (C25); db/ (2770,
# ADR 0013) is created separately by `migrate`, below, under this directory.
run install -d -m 0750 -o "$ADMIN_USER" -g "$SERVICE_GROUP" "$VAR_DIR"
# blobs/ and staging/ pre-created here (rather than left to FsBlobStore's
# own auto-create on first use) so ownership is right regardless of which
# process happens to construct FsBlobStore first. Inside $VAR_DIR: created
# as pdash-admin, never by root (ensure_admin_dir, deploy-1).
ensure_admin_dir "$VAR_DIR/blobs" 0750
ensure_admin_dir "$VAR_DIR/staging" 0750
run install -d -m 0700 -o root -g root "$OUTBOX_DIR"
if [[ "$CLAUDIA" -eq 1 ]]; then
    # KB: root-owned, group pdash-kb read-only for the viewer (C53, C57);
    # writes only through the host's KB tool. Host state + run cwd: root only.
    run install -d -m 0750 -o root -g "$KB_GROUP" "$KB_DIR"
    run install -d -m 0700 -o root -g root "$HOST_STATE_DIR"
    run install -d -m 0700 -o root -g root "$HOST_STATE_DIR/work"
    # Admin-only Claudia DB dir (S-C1 S1): the exact layout connect_claudia
    # demands; the viewer unit masks it on top.
    ensure_admin_dir "$VAR_DIR/claudia" 0700
    # Voice store (FsVoiceStore would create it lazily): made here so it
    # exists BEFORE the viewer restarts below -- a "-" InaccessiblePaths=
    # entry absent at viewer start is silently skipped (deploy-3).
    ensure_admin_dir "$VAR_DIR/voice" 0700
    # The one Claudia dir the viewer may read: the sanitized pending-approvals
    # snapshot the admin writes (M5b) and the knowledge map lists (M8).
    ensure_admin_dir "$VAR_DIR/claudia-view" 0750
fi

# --- 4. sync source into /opt ----------------------------------------------------
# M1 (unit 12 audit): always land the checkout in a fresh temp dir first,
# then `rsync -a --delete` it into $OPT_DIR. A plain `tar -x`/`cp` over an
# existing tree only ever adds/updates files — a file removed from the repo
# since the last install would linger in /opt forever; --delete makes the
# installed tree match the source tree exactly on every re-run. The temp
# dir also means a git checkout and a non-git source tree go through the
# exact same second step (and the same excludes), instead of two code paths
# that could drift apart.
log "sync $REPO_ROOT -> $OPT_DIR"
if [[ "$DRY_RUN" -eq 0 ]]; then
    SYNC_TMP="$(mktemp -d)"
    trap 'rm -rf "$SYNC_TMP"' EXIT
    if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$REPO_ROOT" archive HEAD | tar -x -C "$SYNC_TMP"
    else
        rsync -a \
            --exclude='.venv/' --exclude='.git/' --exclude='__pycache__/' \
            --exclude='*.pyc' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
            --exclude='.ruff_cache/' \
            "$REPO_ROOT/" "$SYNC_TMP/"
    fi
    # Keep src/, deploy/, docs/, pyproject.toml, uv.lock, README/LICENSE
    # (everything a production install needs); exclude dev-only trees that
    # don't belong under /opt on a deployed host.
    rsync -a --delete \
        --exclude='.venv/' --exclude='.claude/' --exclude='tests/' \
        --exclude='HANDOFF.md' --exclude='.github/' \
        "$SYNC_TMP/" "$OPT_DIR/"
    rm -rf "$SYNC_TMP"
    trap - EXIT
    chown -R root:root "$OPT_DIR"
    # go-w: nothing under /opt is meant to be writable by anything but root
    # (the venv it creates next is root-owned too); belt-and-braces on top
    # of the directory modes already set in step 3.
    chmod -R go-w "$OPT_DIR"
    # rsync -a copies the temp dir's own mode (mktemp -d = 0700) onto
    # $OPT_DIR itself; pin it back so the service users can traverse it.
    chmod 0755 "$OPT_DIR"
else
    echo "+ git archive HEAD | tar -x -C <fresh temp dir>   (or rsync if not a git checkout)"
    echo "+ rsync -a --delete --exclude=.venv/ --exclude=.claude/ --exclude=tests/ --exclude=HANDOFF.md --exclude=.github/ <temp dir>/ $OPT_DIR/"
    echo "+ chmod -R go-w $OPT_DIR"
fi

# --- 5. dependencies (frozen, no dev extras) -------------------------------------
log "uv sync --frozen --no-dev"
# Voice (M10): Piper is GPL-3.0, a runtime extra only, never vendored.
_sync_extra=()
if [[ "$VOICE" -eq 1 ]]; then
    _sync_extra=(--extra claudia-voice)
fi
run env -C "$OPT_DIR" "$UV_BIN" sync --frozen --no-dev "${_sync_extra[@]}"
if [[ "$CLAUDIA" -eq 1 ]]; then
    # The host refuses to start without the hook its settings file names
    # (C50/C59); stop here instead of enabling a host that can't run.
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if [[ ! -x "$HOOK_BIN" ]]; then
            echo "error: $HOOK_BIN is missing (C59 hook); not installing Claudia" >&2
            exit 1
        fi
    else
        echo "+ test -x $HOOK_BIN"
    fi
fi

# --- 6. config.toml from the template --------------------------------------------
log "config.toml"
if [[ -e "$CONFIG_FILE" ]]; then
    echo "  $CONFIG_FILE already exists; leaving it in place (edit it directly)"
    if [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        # Only the two notifier keys, only when absent (notify_enabled = false
        # is flipped); owner/mode kept; a different chat id was already
        # refused in step 0 (deploy/lib/notify_config.py).
        _ensure_args=(ensure "$CONFIG_FILE" "$TELEGRAM_CHAT_ID")
        if [[ "$DRY_RUN" -eq 1 ]]; then
            _ensure_args+=(--dry-run)
        fi
        "$PYTHON_BIN" "$NOTIFY_CONFIG_PY" "${_ensure_args[@]}"
    fi
else
    preview_origin="https://${HOST}:8443"
    sed_args=(
        -e "s|^owner_login = \"\"|owner_login = \"${OWNER_LOGIN}\"|"
        -e "s|^allowed_hosts = \[\]|allowed_hosts = [\"${HOST}\"]|"
        -e "s|^preview_origin = \"\"|preview_origin = \"${preview_origin}\"|"
    )
    if [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        sed_args+=(
            -e "s|^notify_enabled = false|notify_enabled = true|"
            -e "s|^# notify_owner_chat_id = 123456789|notify_owner_chat_id = ${TELEGRAM_CHAT_ID}|"
        )
    fi
    sed "${sed_args[@]}" "$SCRIPT_DIR/config.example.toml" | write_file "$CONFIG_FILE" "$CONFIG_FILE_MODE" root:root
fi

# Start the notifier only if config.toml turns it on and its bot token is in
# place; otherwise serve-notifier would exit (disabled) or the unit's
# ConditionPathExists would skip it, and the verify step below would fail.
NOTIFY_ENABLED=0
NOTIFY_START=0
if [[ "$NOTIFIER" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 1 && -n "$TELEGRAM_CHAT_ID" ]]; then
        NOTIFY_ENABLED=1  # the (dry-run, unwritten) edit above turns it on
    else
        # Own statement (not inside [[ ]]) so a parse error stops the install.
        _enabled="$("$PYTHON_BIN" "$NOTIFY_CONFIG_PY" enabled "$CONFIG_FILE")"
        if [[ "$_enabled" == "true" ]]; then
            NOTIFY_ENABLED=1
        fi
    fi
    if [[ "$NOTIFY_ENABLED" -eq 1 ]] && [[ -e "$TELEGRAM_TOKEN_DEST" || -n "$TELEGRAM_TOKEN_FILE" ]]; then
        NOTIFY_START=1
    fi
fi

# --- 7. admin token (never overwritten; gen-token itself refuses to) ------------
log "admin token"
if [[ -e "$TOKEN_FILE" ]]; then
    echo "  $TOKEN_FILE already exists; leaving it in place"
    echo "  (rotate with: preview-dashboard gen-token --out ... then mv; see docs/operations.md)"
else
    # Group is $SERVICE_GROUP ("pdash"): interfaces/mcp/server.py trusts
    # whatever gid actually owns the admin socket (verify_admin_socket, C12,
    # unit 10b M1), never a hardcoded name; serve-admin's own default egid
    # already matches it too (ADR 0017 "G", docs/adr/0017-deployment-hardening.md).
    run "$PDASH_BIN" gen-token --out "$TOKEN_FILE" --group "$SERVICE_GROUP"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        chmod "$TOKEN_FILE_MODE" "$TOKEN_FILE"
        chown root:"$SERVICE_GROUP" "$TOKEN_FILE"
    fi
fi

# --- 7b. notifier + Telegram bot tokens (notifier installed, step 0) -------------
if [[ "$NOTIFIER" -eq 1 ]]; then
    log "notifier token"
    if [[ -e "$NOTIFIER_TOKEN_FILE" ]]; then
        echo "  $NOTIFIER_TOKEN_FILE already exists; leaving it in place"
    else
        # root:pdash-notifytok (C36): the admin service verifies it (needs
        # --token-group notifier=pdash-notifytok, wired via notifier-admin.env
        # below), the notifier service presents it.
        run "$PDASH_BIN" gen-token --out "$NOTIFIER_TOKEN_FILE" --group "$NOTIFY_TOK_GROUP"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            chmod "$TOKEN_FILE_MODE" "$NOTIFIER_TOKEN_FILE"
            chown root:"$NOTIFY_TOK_GROUP" "$NOTIFIER_TOKEN_FILE"
        fi
    fi

    log "Telegram bot token"
    if [[ -e "$TELEGRAM_TOKEN_DEST" ]]; then
        echo "  $TELEGRAM_TOKEN_DEST already exists; leaving it in place"
    elif [[ -n "$TELEGRAM_TOKEN_FILE" ]]; then
        # Never echoed, never taken as a CLI argument value beyond a path --
        # only the *path* to a file the operator already created is given.
        run install -m "$TOKEN_FILE_MODE" -o root -g "$NOTIFY_USER" \
            "$TELEGRAM_TOKEN_FILE" "$TELEGRAM_TOKEN_DEST"
    else
        echo "  no --telegram-token-file given: place the bot token yourself, e.g."
        echo "    install -m 0640 -o root -g $NOTIFY_USER <your-token-file> $TELEGRAM_TOKEN_DEST"
        echo "  (root:$NOTIFY_USER 0640 -- only the notifier reads it, C36)"
    fi

    # Admin needs --notifier-peer-uid (ADR 0022) and --token-group
    # notifier=pdash-notifytok (C36, scoped to that file: ADR 0024) to accept
    # and validate notifier.token; written to
    # an env file the admin unit sources optionally (EnvironmentFile=-),
    # so the shipped preview-dashboard-admin.service never changes per host.
    log "admin notifier args -> $NOTIFIER_ADMIN_ENV"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        NOTIFY_UID="$(id -u "$NOTIFY_USER")"
    else
        NOTIFY_UID="<resolved-at-install-time>"
    fi
    if [[ "$DRY_RUN" -eq 0 && ! "$NOTIFY_UID" =~ ^[0-9]+$ ]]; then
        echo "error: could not resolve a numeric uid for $NOTIFY_USER" >&2
        exit 1
    fi
    # One line, unquoted value: the admin unit expands it UNBRACED
    # ($PDASH_NOTIFIER_ADMIN_ARGS), i.e. split into separate argv words (H1).
    printf 'PDASH_NOTIFIER_ADMIN_ARGS=--notifier-peer-uid %s --token-group notifier=%s\n' \
        "$NOTIFY_UID" "$NOTIFY_TOK_GROUP" | write_file "$NOTIFIER_ADMIN_ENV" 0644 root:root
elif [[ -e "$NOTIFIER_ADMIN_ENV" ]]; then
    # Left over after `uninstall.sh --purge-users`: it names a deleted uid
    # and group, which would make serve-admin refuse to start.
    run rm -f "$NOTIFIER_ADMIN_ENV"
fi

# --- 7c. Claudia files (Claudia installed, step 0b; M9, ADR 0036) -----------------
if [[ "$CLAUDIA" -eq 1 ]]; then
    log "claudia token"
    if [[ -e "$CLAUDIA_TOKEN_FILE" ]]; then
        echo "  $CLAUDIA_TOKEN_FILE already exists; leaving it in place"
    else
        # root:pdash-claudiatok 0640 (C45/C12): the admin verifies it (member),
        # the host presents it (unit Group=); never in env/argv/logs.
        run "$PDASH_BIN" gen-token --out "$CLAUDIA_TOKEN_FILE" --group "$CLAUDIA_TOK_GROUP"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            chmod "$TOKEN_FILE_MODE" "$CLAUDIA_TOKEN_FILE"
            chown root:"$CLAUDIA_TOK_GROUP" "$CLAUDIA_TOKEN_FILE"
        fi
    fi

    log "TOTP secret"
    # Never created here (C47): setup is interactive, on the owner's terminal.
    if [[ -e "$TOTP_SECRET_FILE" ]]; then
        echo "  $TOTP_SECRET_FILE already exists; leaving it in place"
    else
        echo "  $TOTP_SECRET_FILE is missing: the owner creates it (the host won't start without it):"
        echo "    $PDASH_BIN claudia totp setup --group $TOTP_GROUP"
    fi

    log "Claudia host settings + MCP config"
    # Repo-controlled, so replaced on every run: root 0644, verified by the
    # host at start (C50) -- deny rules + the C59/C60 hook entry.
    run install -m 0644 -o root -g root "$CLAUDIA_SETTINGS_SRC" "$CLAUDIA_SETTINGS_DEST"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        KB_GID="$("$GETENT_BIN" group "$KB_GROUP" | cut -d: -f3)"
        if [[ ! "$KB_GID" =~ ^[0-9]+$ ]]; then
            echo "error: could not resolve a numeric gid for $KB_GROUP" >&2
            exit 1
        fi
    else
        KB_GID="<resolved-at-install-time>"
    fi
    if [[ ! -r "$CLAUDIA_MCP_TEMPLATE" ]]; then
        echo "ERROR: cannot read $CLAUDIA_MCP_TEMPLATE (Claudia MCP config, C51)" >&2
        exit 1
    fi
    sed -e '/^#/d' -e "s|@KB_GID@|${KB_GID}|" "$CLAUDIA_MCP_TEMPLATE" \
        | write_file "$CLAUDIA_MCP_DEST" 0644 root:root

    # Host + gardener units read these (both required there: fail closed).
    printf 'PDASH_CLAUDE_BIN=%s\nPDASH_KB_GID=%s\n' "$CLAUDE_BIN" "$KB_GID" \
        | write_file "$CLAUDIA_ENV" 0644 root:root
    # Admin args, UNBRACED in its ExecStart like the notifier's (H1). Peer uid
    # 0: the host runs as root; groups scoped to their one file each.
    log "admin Claudia args -> $CLAUDIA_ADMIN_ENV"
    printf 'PDASH_CLAUDIA_ADMIN_ARGS=--claudia-peer-uid 0 --token-group claudia=%s --token-group totp=%s\n' \
        "$CLAUDIA_TOK_GROUP" "$TOTP_GROUP" | write_file "$CLAUDIA_ADMIN_ENV" 0644 root:root

    if [[ -n "$VOICE_MODELS" ]]; then
        # deploy-6: copy FIRST into a root-only staging dir, then hash the
        # copies: checking $VOICE_MODELS and copying afterwards would let
        # anyone who can write that dir swap a file in between (TOCTOU).
        log "voice models (pinned SHA-256, $VOICE_PINS)"
        run install -d -m 0700 -o root -g root "$VOICES_STAGING"
        for f in "${VOICE_FILES[@]}"; do
            run install -m 0600 -o root -g root "$VOICE_MODELS/$f" "$VOICES_STAGING/$f"
        done
        if ! verify_voices "$VOICES_STAGING"; then
            for f in "${VOICE_FILES[@]}"; do
                run rm -f -- "$VOICES_STAGING/$f"
            done
            run rmdir -- "$VOICES_STAGING"
            echo "error: a voice model from $VOICE_MODELS does not match its pinned SHA-256" >&2
            exit 1
        fi
        run install -d -m 0700 -o root -g root "$VOICES_DIR"
        for f in "${VOICE_FILES[@]}"; do
            run mv -f -- "$VOICES_STAGING/$f" "$VOICES_DIR/$f"
        done
        run rmdir -- "$VOICES_STAGING"
    fi
    # Every run re-verifies what Piper will load (deploy-6): a model changed
    # since it was installed stops the install instead of being trusted.
    if [[ "$VOICE" -eq 1 ]] && ! verify_voices "$VOICES_DIR"; then
        echo "error: an installed voice model in $VOICES_DIR does not match its pinned SHA-256" >&2
        echo "       (re-run with --voice-models DIR to replace it)" >&2
        exit 1
    fi
elif [[ -e "$CLAUDIA_ADMIN_ENV" ]]; then
    # Left over after `uninstall.sh --purge-users`: names deleted groups.
    run rm -f "$CLAUDIA_ADMIN_ENV"
fi

# --- 8. validate config, then create/migrate the schema -------------------------
# --token-group: check-config runs as root here, whose own egid (0) does
# not match the token file's group ($SERVICE_GROUP) by default. H2 (S-B):
# with the notifier installed, notifier.token is root:pdash-notifytok and
# check-config loads it too (notify_enabled), so trust that group as well.
# Scoped KIND=GROUP (ADR 0024): each group is trusted for its own file only,
# so a token left in the other file's group is caught here.
log "check-config"
_check_extra=()
if [[ "$NOTIFIER" -eq 1 ]]; then
    _check_extra=(--token-group "notifier=$NOTIFY_TOK_GROUP")
fi
if [[ "$CLAUDIA" -eq 1 ]]; then
    # check-config loads claudia.token too when claudia_enabled (C45).
    _check_extra+=(--token-group "claudia=$CLAUDIA_TOK_GROUP")
fi
run env PDASH_CONFIG="$CONFIG_FILE" "$PDASH_BIN" check-config --token-group "admin=$SERVICE_GROUP" "${_check_extra[@]}"

log "migrate (as $ADMIN_USER)"
# --trusted-sidecar-uid: on a re-run the viewer is still up and may own -wal/-shm.
run runuser --user "$ADMIN_USER" -- env PDASH_CONFIG="$CONFIG_FILE" "$PDASH_BIN" migrate \
    --trusted-sidecar-uid "$VIEWER_UID"

# --- 9. systemd units --------------------------------------------------------------
log "systemd units"
run install -d -m 0755 "$SYSTEMD_DIR"
for unit in preview-dashboard-admin.service preview-dashboard-viewer.service \
    preview-dashboard-purge.service preview-dashboard-purge.timer \
    preview-dashboard-firewall.service; do
    run install -m 0644 "$SCRIPT_DIR/systemd/$unit" "$SYSTEMD_DIR/$unit"
done
if [[ "$NOTIFIER" -eq 1 ]]; then
    run install -m 0644 "$SCRIPT_DIR/systemd/preview-dashboard-notifier.service" \
        "$NOTIFIER_UNIT_DEST"
fi
if [[ "$CLAUDIA" -eq 1 ]]; then
    for unit in claudia-host.service claudia-gardener.service claudia-gardener.timer; do
        run install -m 0644 "$SCRIPT_DIR/systemd/$unit" "$SYSTEMD_DIR/$unit"
    done
fi
run systemctl daemon-reload

# --- 10. loopback firewall (C14, C38) -----------------------------------------------
# Own table only, loaded by a dedicated oneshot unit. Never edits
# /etc/nftables.conf or enables nftables.service: Ubuntu's default config
# starts with `flush ruleset`, which would wipe tailscaled's rules.
log "loopback firewall"
if [[ "$NOTIFIER" -eq 1 ]]; then
    # Replace the single "__PDASH_NOTIFIER_EGRESS__" comment line with
    # pdash-notify's outbound rules from nftables/notifier-egress.nft.in
    # (its own "#" header lines dropped). Numeric uid (checked in step 7b):
    # nft resolves usernames at load time, which would fail the *whole
    # table* on a host where that user doesn't exist.
    echo "  notifier egress rules (C38) for uid $NOTIFY_UID from $NOTIFY_EGRESS_TEMPLATE"
    # F-C item 1: fail closed if the template can't even be opened -- silently
    # falling through here would ship a table missing pdash-notify's egress
    # rules (an unrestricted exit instead of the C38 allowlist).
    if [[ ! -r "$NOTIFY_EGRESS_TEMPLATE" ]]; then
        echo "ERROR: cannot read $NOTIFY_EGRESS_TEMPLATE (notifier egress rules, C38)" >&2
        exit 1
    fi
    awk -v uid="$NOTIFY_UID" -v tpl="$NOTIFY_EGRESS_TEMPLATE" '
        /# __PDASH_NOTIFIER_EGRESS__/ {
            spliced = 0
            while ((rc = (getline line < tpl)) > 0) {
                if (line ~ /^#/) continue
                gsub(/@NOTIFY_UID@/, uid, line)
                print line
                spliced++
            }
            close(tpl)
            if (rc < 0) {
                print "awk: error reading " tpl > "/dev/stderr"
                exit 1
            }
            if (spliced == 0) {
                print "awk: no notifier egress rules spliced from " tpl > "/dev/stderr"
                exit 1
            }
            next
        }
        { print }
    ' "$SCRIPT_DIR/nftables/preview-dashboard.nft" | write_file "$ETC_DIR/preview-dashboard.nft" 0644 root:root
else
    write_file "$ETC_DIR/preview-dashboard.nft" 0644 root:root <"$SCRIPT_DIR/nftables/preview-dashboard.nft"
fi
run systemctl enable preview-dashboard-firewall.service

# --- 11. enable services -----------------------------------------------------------
# H2 (unit 12 audit): enable only here, restart explicitly in the next step.
# `systemctl enable --now` on a unit that is already active is a no-op for
# the "now" part — it does NOT restart it, so a re-run after `git pull` would
# leave the *old* code running under a freshly-updated unit file. purge.timer
# has no such concern (a oneshot triggered hourly, nothing to "update in
# place"), so it keeps the simpler `enable --now`.
log "enable services"
run systemctl enable preview-dashboard-admin.service
run systemctl enable preview-dashboard-viewer.service
run systemctl enable --now preview-dashboard-purge.timer
if [[ "$NOTIFIER" -eq 1 && "$NOTIFY_ENABLED" -eq 1 ]]; then
    run systemctl enable preview-dashboard-notifier.service
elif [[ "$NOTIFIER" -eq 1 ]]; then
    # Installed but off in config.toml: serve-notifier would only exit.
    echo "  notify_enabled is not true in $CONFIG_FILE: notifier installed but not enabled"
    run systemctl disable --now preview-dashboard-notifier.service
fi
# Claudia: only the owner turns claudia_enabled on (config.toml); this
# script only reads it. Off -> host + gardener stay disabled (and stopped).
CLAUDIA_ENABLED=0
CLAUDIA_START=0
if [[ "$CLAUDIA" -eq 1 ]]; then
    # Own statement so a parse error stops the install (as for notify).
    _claudia_on="$("$PYTHON_BIN" "$NOTIFY_CONFIG_PY" enabled --key claudia_enabled "$CONFIG_FILE")"
    if [[ "$_claudia_on" == "true" ]]; then
        CLAUDIA_ENABLED=1
        run systemctl enable claudia-host.service
        run systemctl enable --now claudia-gardener.timer
        if [[ -e "$TOTP_SECRET_FILE" ]]; then
            CLAUDIA_START=1
        fi
    else
        echo "  claudia_enabled is not true in $CONFIG_FILE: Claudia installed but not enabled"
        run systemctl disable --now claudia-host.service claudia-gardener.timer
    fi
fi

# --- 12. restart + verify ------------------------------------------------------------
# Firewall first (the viewer Requires= it — restarting it briefly reloads
# the nft table, atomically per deploy/nftables/preview-dashboard.nft, never
# leaving a gap), then admin, then viewer: always picks up the code/unit
# file just installed, whether this is a first install or a re-run.
log "restart services (picks up any code/unit file update)"
run systemctl restart preview-dashboard-firewall preview-dashboard-admin preview-dashboard-viewer
# Kept separate from the line above (not folded into one `systemctl restart`
# call): that line's exact shape is depended on where the notifier doesn't
# exist at all (no --telegram-chat-id), so a plain install's restart step
# stays byte-identical to before N5.
if [[ "$NOTIFY_START" -eq 1 ]]; then
    run systemctl restart preview-dashboard-notifier
elif [[ "$NOTIFY_ENABLED" -eq 1 ]]; then
    echo "  $TELEGRAM_TOKEN_DEST is missing: notifier enabled but not started (place it, then"
    echo "  systemctl start preview-dashboard-notifier; docs/operations.md)"
fi
# After the admin (it re-reads claudia-admin.env) and the notifier.
if [[ "$CLAUDIA_START" -eq 1 ]]; then
    run systemctl restart claudia-host
elif [[ "$CLAUDIA_ENABLED" -eq 1 ]]; then
    echo "  $TOTP_SECRET_FILE is missing: claudia-host enabled but not started (run"
    echo "  $PDASH_BIN claudia totp setup --group $TOTP_GROUP, then re-run install.sh)"
fi

log "verify units are current and active"
_verify_units=(preview-dashboard-firewall.service preview-dashboard-admin.service
    preview-dashboard-viewer.service)
if [[ "$NOTIFY_START" -eq 1 ]]; then
    _verify_units+=(preview-dashboard-notifier.service)
fi
if [[ "$CLAUDIA_START" -eq 1 ]]; then
    _verify_units+=(claudia-host.service)
fi
if [[ "$DRY_RUN" -eq 0 ]]; then
    for unit in "${_verify_units[@]}"; do
        need_reload="$(systemctl show "$unit" --property=NeedDaemonReload --value)"
        if [[ "$need_reload" != "no" ]]; then
            echo "error: $unit still needs a daemon-reload after restart" >&2
            exit 1
        fi
        if ! systemctl is-active --quiet "$unit"; then
            echo "error: $unit is not active after restart" >&2
            exit 1
        fi
        echo "  $unit: NeedDaemonReload=no, active"
    done
else
    for unit in "${_verify_units[@]}"; do
        echo "+ systemctl show $unit --property=NeedDaemonReload --value"
        echo "+ systemctl is-active --quiet $unit"
    done
fi

# --- 13. report -----------------------------------------------------------------
log "status"
_status_units=(preview-dashboard-admin.service preview-dashboard-viewer.service
    preview-dashboard-purge.timer)
_analyzed_units=(preview-dashboard-admin.service preview-dashboard-viewer.service
    preview-dashboard-purge.service)
if [[ "$NOTIFIER" -eq 1 ]]; then
    _status_units+=(preview-dashboard-notifier.service)
    _analyzed_units+=(preview-dashboard-notifier.service)
fi
if [[ "$CLAUDIA" -eq 1 ]]; then
    # Not analyzed: a root agent host is deliberately unsandboxed (ADR 0036).
    _status_units+=(claudia-host.service claudia-gardener.timer)
fi
if [[ "$DRY_RUN" -eq 0 ]]; then
    systemctl --no-pager --full status "${_status_units[@]}" || true
    echo
    echo "systemd-analyze security (target: <= 2.0 per unit, docs/security.md C28):"
    systemd-analyze security "${_analyzed_units[@]}" || true
else
    echo "(dry run: status and systemd-analyze security skipped)"
fi

# --- 14. live verification (M2, unit 12 audit) ---------------------------------------
# Read-only: never restarts/reconfigures anything. Some checks (the
# self-connect ones against https://<host>) are no-ops before `tailscale up`
# + serve.sh have run (step 4 below) — deploy/check.sh skips those instead
# of failing when it can't determine the tailnet IP yet.
log "live verification (deploy/check.sh)"
if [[ "$DRY_RUN" -eq 0 ]]; then
    "$SCRIPT_DIR/check.sh" --config "$CONFIG_FILE" --bin "$PDASH_BIN"
else
    echo "+ $SCRIPT_DIR/check.sh --config $CONFIG_FILE --bin $PDASH_BIN"
fi

cat <<EOF

Next steps (owner actions, see docs/operations.md):
  1. tailscale up   (enroll this host in the tailnet, if not already)
  2. sudo deploy/tailscale/serve.sh   (fronts 8787->443, 8788->8443; verifies Funnel off)
  3. Merge deploy/tailscale/acl-snippet.json into the tailnet ACL (restrict to the owner)
  4. Register the MCP server for Claude Code (docs/operations.md, C30: no secrets in its env)
EOF

if [[ "$NOTIFIER" -eq 1 ]]; then
    cat <<EOF
  5. Pair the bot with your chat (stop the notifier first if it's already
     running, then run as root -- --token-group telegram=... lets root
     read telegram.token, which is root:$NOTIFY_USER 0640):
       systemctl stop preview-dashboard-notifier
       $PDASH_BIN notify pair --token-group telegram=$NOTIFY_USER
       systemctl start preview-dashboard-notifier
     ("notify pair" prints the chat id -- confirm it matches
     notify_owner_chat_id in $CONFIG_FILE, else edit that line by hand and
     systemctl restart preview-dashboard-admin preview-dashboard-notifier.)
  6. Send a test alert (asks the admin API as root; no --token-group needed):
       $PDASH_BIN notify test
EOF
fi

if [[ "$CLAUDIA" -eq 1 ]]; then
    cat <<EOF
  7. Claudia (docs/operations.md "Claudia"): log in to Claude Code as root
     with the subscription ($CLAUDE_BIN; never an API key, C49).
  8. Create the authenticator secret on this terminal (once):
       $PDASH_BIN claudia totp setup --group $TOTP_GROUP
  9. Turn her on: set claudia_enabled = true in $CONFIG_FILE, then re-run
     install.sh (enables + starts claudia-host and the weekly gardener).
EOF
fi
