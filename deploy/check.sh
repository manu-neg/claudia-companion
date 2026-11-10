#!/usr/bin/env bash
# deploy/check.sh — read-only, LIVE verification of an installed
# preview-dashboard host (unit 12 audit fix batch, M2).
#
# Unlike tests/unit/test_deploy_artifacts.py (which only parses/lints the
# artifacts in this repo and never touches a running system), this script
# checks the actual, currently-running deployment: firewall state, service
# freshness, sandbox confinement, exposure score and Tailscale exposure.
# It never writes, deletes, restarts or reconfigures anything — only reads
# state (nft ruleset, systemctl properties, `systemd-analyze security`,
# `tailscale ... status`) and makes a handful of read-only HTTP requests to
# the viewer's own ports (plus, with claudia_enabled, the Claudia host,
# gardener timer, file modes and the viewer's KB confinement). Must run as root (needed to read service PIDs,
# enter the viewer's mount namespace read-only, and query nftables).
#
# Usage: sudo deploy/check.sh [--config PATH] [--bin PATH]
#
# Exit code: 0 if every check passed, 1 if any failed or the environment
# itself is unusable (fail closed, docs/security.md I6). `deploy/install.sh`
# runs this as its last step; also safe to re-run any time by hand
# (docs/operations.md "Verify").
set -euo pipefail

CONFIG_FILE=""
PDASH_BIN="${PDASH_BIN:-/opt/preview-dashboard/.venv/bin/preview-dashboard}"
VENV_PYTHON="${VENV_PYTHON:-/opt/preview-dashboard/.venv/bin/python}"

usage() {
    cat <<'EOF'
usage: check.sh [--config PATH] [--bin PATH]

  --config PATH   config.toml to validate (default: the installed
                   binary's own default, /etc/preview-dashboard/config.toml,
                   or $PDASH_CONFIG)
  --bin PATH       preview-dashboard executable to use for `check-config`
                   (default: $PDASH_BIN or
                   /opt/preview-dashboard/.venv/bin/preview-dashboard)
  -h, --help       show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_FILE="${2:?--config needs a value}"
            shift 2
            ;;
        --bin)
            PDASH_BIN="${2:?--bin needs a value}"
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

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: deploy/check.sh must run as root (reads other users' process" >&2
    echo "state, nftables, and the admin token's protections read-only)" >&2
    exit 1
fi

FAILURES=0
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}
skip() { echo "SKIP: $*"; }
# A warning does not fail the check (the service works; one panel is degraded).
warn() { echo "WARN: $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- config: reuse the real, validated settings loader (never a hand-rolled
# TOML parse) so this script fails the same way the services would ----------
read_config_summary() {
    local json
    if [[ -n "$CONFIG_FILE" ]]; then
        json="$(PDASH_CONFIG="$CONFIG_FILE" "$PDASH_BIN" check-config --skip-token 2>&1)" || {
            echo "error: 'preview-dashboard check-config' failed:" >&2
            echo "$json" >&2
            exit 1
        }
    else
        json="$("$PDASH_BIN" check-config --skip-token 2>&1)" || {
            echo "error: 'preview-dashboard check-config' failed:" >&2
            echo "$json" >&2
            exit 1
        }
    fi
    printf '%s\n' "$json"
}

# --- C14: nftables — our own table + tailscaled's own chains still intact --
check_nft_table() {
    if ! have nft; then
        fail "nft is not installed"
        return
    fi
    local out
    if ! out="$(nft list table inet preview_dashboard 2>&1)"; then
        fail "nft table inet preview_dashboard is not loaded ($out) — run: systemctl restart preview-dashboard-firewall"
        return
    fi
    if grep -q 'meta skuid 0 accept' <<<"$out" \
        && grep -q 'dport { 8787, 8788 }' <<<"$out" \
        && grep -q 'dport { 443, 8443 }' <<<"$out"; then
        pass "nft table inet preview_dashboard is loaded with the loopback + local-fib (H1) rules"
    else
        fail "nft table inet preview_dashboard is loaded but is missing expected rules"
    fi

    local ruleset
    ruleset="$(nft list ruleset 2>/dev/null)" || ruleset=""
    if grep -q 'chain ts-input' <<<"$ruleset"; then
        pass "tailscaled's own ts-* chains are still present (nothing flushed the whole ruleset)"
    else
        fail "tailscaled's ts-* chains are missing — something ran 'flush ruleset'; see" \
            "docs/operations.md 'Network exposure' recovery step"
    fi
}

# --- C14 + H1: a non-root local user must be refused on every gated port ---
check_nobody_refused() {
    local host="$1"
    if ! id nobody >/dev/null 2>&1; then
        skip "no 'nobody' user on this host; cannot test uid-based refusal"
        return
    fi
    if ! have curl || ! have runuser; then
        fail "curl or runuser is not installed"
        return
    fi

    local target
    for target in "http://127.0.0.1:8787/|dashboard loopback port 8787" \
        "http://127.0.0.1:8788/|preview loopback port 8788"; do
        local url="${target%%|*}" desc="${target#*|}"
        if runuser -u nobody -- curl --max-time 3 -sS -o /dev/null "$url" >/dev/null 2>&1; then
            fail "local user 'nobody' was NOT refused connecting to $desc"
        else
            pass "local user 'nobody' is refused connecting to $desc"
        fi
    done

    if ! have tailscale; then
        skip "tailscale not installed; skipping self-connect (H1) checks against https://$host"
        return
    fi
    local tsip
    tsip="$(tailscale ip -4 2>/dev/null | head -n1)" || tsip=""
    if [[ -z "$tsip" ]]; then
        skip "could not determine this host's tailnet IPv4; skipping self-connect (H1) checks"
        return
    fi

    for target in "https://${host}/|self tailnet https 443 (${host})" \
        "https://${host}:8443/|self tailnet https 8443 (${host})"; do
        local url="${target%%|*}" desc="${target#*|}"
        if runuser -u nobody -- curl --max-time 5 -sS -k \
            --resolve "${host}:443:${tsip}" --resolve "${host}:8443:${tsip}" \
            -o /dev/null "$url" >/dev/null 2>&1; then
            fail "local user 'nobody' was NOT refused self-connecting to $desc" \
                "(H1: tailscale serve self-attribution rule missing/broken)"
        else
            pass "local user 'nobody' is refused self-connecting to $desc (H1)"
        fi
    done
}

# --- identity check: a request with no Tailscale-User-Login header must be
# refused by the app itself, independent of the network-layer rules above --
check_no_identity_403() {
    local host="$1"
    if ! have curl; then
        fail "curl is not installed"
        return
    fi
    # Each app's IdentityMiddleware does an EXACT Host match (C3): the
    # dashboard's is the bare hostname (443 is the default HTTPS port, so
    # `tailscale serve` forwards Host without it); the preview origin is a
    # non-default port, so its Host includes ":8443" (app_factory.py
    # `origins.preview_host`).
    local entry
    for entry in "8787|dashboard|${host}" "8788|preview|${host}:8443"; do
        local port desc host_header
        port="${entry%%|*}"
        desc="${entry#*|}"
        desc="${desc%%|*}"
        host_header="${entry##*|}"
        local code
        # Retry "000" (no connection) for ~10s: install.sh runs this right
        # after restarting the viewer, which may not be listening yet.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            code="$(curl --max-time 3 -sS -o /dev/null -w '%{http_code}' \
                -H "Host: ${host_header}" "http://127.0.0.1:${port}/" 2>/dev/null)" || code="000"
            [[ "$code" != "000" ]] && break
            sleep 1
        done
        if [[ "$code" == "403" ]]; then
            pass "$desc app refuses a request with no Tailscale identity header (403)"
        else
            fail "$desc app returned HTTP $code (expected 403) for a request with no" \
                "Tailscale-User-Login header"
        fi
    done
}

# --- services: active, unit file not stale, restarted after last change ---
_CHECKED_UNITS=(preview-dashboard-firewall.service preview-dashboard-admin.service
    preview-dashboard-viewer.service)

check_services_fresh_and_active() {
    local unit
    for unit in "${_CHECKED_UNITS[@]}"; do
        local path="/etc/systemd/system/${unit}"
        if [[ ! -e "$path" ]]; then
            fail "$unit: unit file not installed at $path"
            continue
        fi
        local active_state need_reload ts
        active_state="$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)" || active_state=""
        need_reload="$(systemctl show "$unit" --property=NeedDaemonReload --value 2>/dev/null)" || need_reload=""
        if [[ "$active_state" != "active" ]]; then
            fail "$unit: not active (ActiveState=${active_state:-unknown})"
            continue
        fi
        if [[ "$need_reload" != "no" ]]; then
            fail "$unit: needs 'systemctl daemon-reload' (unit file changed since it was loaded)"
            continue
        fi
        ts="$(systemctl show "$unit" --property=ActiveEnterTimestamp --value 2>/dev/null)" || ts=""
        local active_epoch unit_mtime
        active_epoch="$(date -d "$ts" +%s 2>/dev/null)" || active_epoch=0
        unit_mtime="$(stat -c %Y "$path" 2>/dev/null)" || unit_mtime=0
        if [[ "$active_epoch" -ge "$unit_mtime" ]]; then
            pass "$unit: active, NeedDaemonReload=no, started after its unit file was last installed"
        else
            fail "$unit: last (re)started before its unit file was last installed/updated" \
                "-- run: systemctl restart preview-dashboard-firewall preview-dashboard-admin" \
                "preview-dashboard-viewer (docs/operations.md 'Updating')"
        fi
    done
}

# --- C20/C28: the viewer's own mount namespace must actually hide /root and
# the admin token, not just "the file happens to be group-unreadable" -------
check_viewer_confinement() {
    if ! have nsenter; then
        fail "nsenter is not installed; cannot verify viewer mount-namespace confinement"
        return
    fi
    if ! id pdash-viewer >/dev/null 2>&1; then
        skip "pdash-viewer user does not exist on this host"
        return
    fi
    local pid
    pid="$(systemctl show preview-dashboard-viewer.service --property=MainPID --value 2>/dev/null)" || pid=""
    if [[ -z "$pid" || "$pid" == "0" ]]; then
        fail "preview-dashboard-viewer.service has no MainPID (not running?)"
        return
    fi

    # -r, not -e: InaccessiblePaths=/ProtectHome= replace the target with a
    # 0-byte/0-mode placeholder rather than removing it, so it still stat()s
    # as "exists" — the load-bearing property is that it can't be *read*.
    if nsenter --mount="/proc/${pid}/ns/mnt" -- \
        runuser -u pdash-viewer -g pdash -- test -r /etc/preview-dashboard/admin.token 2>/dev/null; then
        fail "the viewer process CAN read /etc/preview-dashboard/admin.token (InaccessiblePaths not effective)"
    else
        pass "the viewer process cannot read /etc/preview-dashboard/admin.token (InaccessiblePaths)"
    fi

    if nsenter --mount="/proc/${pid}/ns/mnt" -- \
        runuser -u pdash-viewer -g pdash -- test -r /root 2>/dev/null; then
        fail "the viewer process CAN read /root (ProtectHome not effective)"
    else
        pass "the viewer process cannot read /root (ProtectHome=yes)"
    fi
}

# --- C28: systemd-analyze security exposure ---------------------------------
_ANALYZED_UNITS=(preview-dashboard-admin.service preview-dashboard-viewer.service
    preview-dashboard-purge.service)
_SECURITY_THRESHOLD="2.0"

check_systemd_analyze_security() {
    if ! have systemd-analyze; then
        fail "systemd-analyze is not installed"
        return
    fi
    local unit
    for unit in "${_ANALYZED_UNITS[@]}"; do
        local out score
        out="$(systemd-analyze security "$unit" --no-pager 2>&1)" || true
        score="$(grep -oE 'Overall exposure level for [^:]+: [0-9.]+' <<<"$out" \
            | grep -oE '[0-9.]+$')" || score=""
        if [[ -z "$score" ]]; then
            fail "$unit: could not parse the 'systemd-analyze security' exposure score"
            continue
        fi
        if awk -v s="$score" -v t="$_SECURITY_THRESHOLD" 'BEGIN { exit !(s <= t) }'; then
            pass "$unit: systemd-analyze security exposure $score <= $_SECURITY_THRESHOLD"
        else
            fail "$unit: systemd-analyze security exposure $score > $_SECURITY_THRESHOLD"
        fi
    done
}

# --- C33/C36/C38: the notifier, only when configured (notify_enabled) ------
check_notifier() {
    local config_json="$1"
    local enabled
    enabled="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["notify_enabled"])' \
        <<<"$config_json" 2>/dev/null)" || enabled="False"
    if [[ "$enabled" != "True" ]]; then
        skip "notify_enabled = false; skipping notifier checks"
        return
    fi

    if ! id pdash-notify >/dev/null 2>&1; then
        fail "notify_enabled = true but the pdash-notify user does not exist" \
            "(re-run install.sh --telegram-chat-id ...)"
        return
    fi

    if systemctl is-active --quiet preview-dashboard-notifier.service; then
        pass "preview-dashboard-notifier.service is active"
    else
        fail "preview-dashboard-notifier.service is not active" \
            "(ActiveState=$(systemctl show preview-dashboard-notifier.service --property=ActiveState --value 2>/dev/null))"
    fi

    local main_user
    main_user="$(ps -o user= -p "$(systemctl show preview-dashboard-notifier.service \
        --property=MainPID --value 2>/dev/null)" 2>/dev/null)" || main_user=""
    if [[ "$main_user" == "pdash-notify" ]]; then
        pass "preview-dashboard-notifier runs as pdash-notify"
    else
        fail "preview-dashboard-notifier's main process user is '${main_user:-unknown}', not pdash-notify"
    fi

    # File modes/owners, never printing contents.
    local f owner mode expect_owner
    for f in "/etc/preview-dashboard/telegram.token|root:pdash-notify" \
        "/etc/preview-dashboard/notifier.token|root:pdash-notifytok"; do
        local path="${f%%|*}"
        expect_owner="${f#*|}"
        if [[ ! -e "$path" ]]; then
            fail "$path does not exist"
            continue
        fi
        owner="$(stat -c '%U:%G' "$path" 2>/dev/null)" || owner=""
        mode="$(stat -c '%a' "$path" 2>/dev/null)" || mode=""
        if [[ "$owner" == "$expect_owner" && "$mode" == "640" ]]; then
            pass "$path is $expect_owner mode 640"
        else
            fail "$path is ${owner:-?} mode ${mode:-?} (expected $expect_owner mode 640)"
        fi
    done

    # The admin process must never be able to read the bot token: only
    # pdash-notify's own primary group owns it (C33).
    if have runuser; then
        if runuser -u pdash-admin -- test -r /etc/preview-dashboard/telegram.token 2>/dev/null; then
            fail "pdash-admin CAN read telegram.token (should be root:pdash-notify only)"
        else
            pass "pdash-admin cannot read telegram.token"
        fi
    else
        skip "runuser not installed; cannot check telegram.token isolation"
    fi

    # nft egress rule scoped to the notifier's uid (C38).
    local notify_uid ruleset
    notify_uid="$(id -u pdash-notify)"
    ruleset="$(nft list table inet preview_dashboard 2>/dev/null)" || ruleset=""
    if grep -q "meta skuid $notify_uid tcp dport 443" <<<"$ruleset"; then
        pass "nft egress rule for pdash-notify (uid $notify_uid) is loaded"
    else
        fail "no nft egress rule for pdash-notify (uid $notify_uid) -- restart" \
            "preview-dashboard-firewall after re-running install.sh"
    fi
    # L2 (S-B): the tailnet/private refusals must sit in front of the 443 accept.
    local private_line accept_line
    private_line="$(grep -nE "meta skuid $notify_uid .*100\.64\.0\.0/10.*reject" <<<"$ruleset" \
        | head -n1 | cut -d: -f1)" || private_line=""
    accept_line="$(grep -n "meta skuid $notify_uid tcp dport 443" <<<"$ruleset" \
        | head -n1 | cut -d: -f1)" || accept_line=""
    if [[ -n "$private_line" && -n "$accept_line" && "$private_line" -lt "$accept_line" ]]; then
        pass "pdash-notify is refused tailnet/private destinations before its 443 accept"
    else
        fail "the nft tailnet/private refusal for pdash-notify is missing or after its 443 accept" \
            "-- re-run install.sh"
    fi

    # M3 (S-B): pdash-notify must reach the admin socket, via the admin
    # unit's POSIX ACL grant only (it is not in group pdash, ADR 0023).
    if runuser -u pdash-notify -- test -w /run/preview-dashboard/admin.sock 2>/dev/null; then
        pass "pdash-notify can open the admin socket (ACL grant applied)"
    else
        fail "pdash-notify cannot open /run/preview-dashboard/admin.sock -- is 'acl' installed?" \
            "(apt install acl; systemctl restart preview-dashboard-admin preview-dashboard-notifier)"
    fi

    check_token_scope
}

# One HTTP probe on the admin socket, as user $1 (root or pdash-notify), with
# the bearer token read from file $2, method $3, path $4; prints the status.
# M1 (S-B): the token only ever travels on stdin (`curl -H @-`, fed by the
# `printf` builtin), never on any process's argv (visible in /proc to every
# local user); `read` is a builtin too.
probe_admin_socket() {
    local user="$1" token_file="$2" method="$3" path="$4" tok code
    IFS= read -r tok <"$token_file" || true
    code="$(printf 'Authorization: Bearer %s\n' "$tok" \
        | runuser -u "$user" -- curl --max-time 5 -sS -o /dev/null -w '%{http_code}' \
            -X "$method" -H @- -H 'Content-Type: application/json' --data-binary '{}' \
            --unix-socket /run/preview-dashboard/admin.sock "http://localhost${path}" 2>/dev/null)" \
        || code="000"
    unset tok
    printf '%s\n' "$code"
}

# --- C33/C34: token scope per route family, each probe sent from a uid the
# peer policy ALLOWS for that family, so a 403 can only come from the token
# check (M1, S-B); each 403 is paired with a control that proves the same
# uid does get through on its own family. The admin-token-on-notifier-route
# direction is NOT probed live here: that would hand the admin token to a
# curl running as pdash-notify, which must never hold it (C33) -- it is
# proven instead by tests/security/test_admin_notifier_routes.py::test_c33_*
# (S-C, F-C item 2). --------------------------------------------------------
check_token_scope() {
    local admin_tok_file=/etc/preview-dashboard/admin.token
    local notify_tok_file=/etc/preview-dashboard/notifier.token
    if ! have curl || ! have runuser; then
        fail "curl or runuser is not installed; cannot check token scope"
        return
    fi
    if [[ ! -r "$admin_tok_file" || ! -r "$notify_tok_file" || ! -S /run/preview-dashboard/admin.sock ]]; then
        fail "admin/notifier token or admin socket missing; cannot check token scope"
        return
    fi
    # Unknown (all-zero) task id: 404 if the notifier token and uid are
    # accepted; nothing is modified.
    local zero_task=/v1/notifier/tasks/00000000000000000000000000/failed code

    code="$(probe_admin_socket root "$admin_tok_file" GET /v1/health)"
    if [[ "$code" == "200" ]]; then
        pass "root with the admin token reaches /v1/health (control)"
    else
        fail "root with the admin token got HTTP $code on /v1/health (expected 200)"
    fi
    code="$(probe_admin_socket root "$notify_tok_file" GET /v1/health)"
    if [[ "$code" == "403" ]]; then
        pass "an admin route refuses the notifier token (403, from an allowed uid)"
    else
        fail "/v1/health returned HTTP $code for the notifier token as root (expected 403)"
    fi

    code="$(probe_admin_socket pdash-notify "$notify_tok_file" POST "$zero_task")"
    if [[ "$code" == "404" ]]; then
        pass "pdash-notify with the notifier token reaches /v1/notifier/* (control, 404 unknown task)"
    else
        fail "pdash-notify with the notifier token got HTTP $code on /v1/notifier/* (expected 404)"
    fi
}

# owner:group + mode of $1 must equal $2 and $3 (never reads the content).
check_owner_mode() {
    local path="$1" expect_owner="$2" expect_mode="$3" owner mode
    if [[ ! -e "$path" ]]; then
        fail "$path does not exist"
        return
    fi
    owner="$(stat -c '%U:%G' "$path" 2>/dev/null)" || owner=""
    mode="$(stat -c '%a' "$path" 2>/dev/null)" || mode=""
    if [[ "$owner" == "$expect_owner" && "$mode" == "$expect_mode" ]]; then
        pass "$path is $expect_owner mode $expect_mode"
    else
        fail "$path is ${owner:-?} mode ${mode:-?} (expected $expect_owner mode $expect_mode)"
    fi
}

# --- Claudia (M9; C45, C47, C49, C54, C57, C58), only when claudia_enabled ---
check_claudia() {
    local config_json="$1"
    local enabled
    enabled="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["claudia_enabled"])' \
        <<<"$config_json" 2>/dev/null)" || enabled="False"
    if [[ "$enabled" != "True" ]]; then
        skip "claudia_enabled = false; skipping Claudia checks"
        return
    fi

    # Without this path the viewer's approvals panel shows "can't be checked".
    local snapshot_set
    snapshot_set="$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("claudia_approvals_snapshot_set", False))' \
        <<<"$config_json" 2>/dev/null)" || snapshot_set="False"
    if [[ "$snapshot_set" == "True" ]]; then
        pass "claudia_approvals_snapshot is set (viewer approvals panel)"
    else
        warn "claudia_approvals_snapshot is unset: the viewer approvals panel cannot be checked (add the line from config.example.toml)"
    fi

    local unit
    for unit in claudia-host.service claudia-gardener.timer; do
        if systemctl is-active --quiet "$unit"; then
            pass "$unit is active"
        else
            fail "$unit is not active (claudia_enabled = true; re-run install.sh)"
        fi
    done

    # C49: no API credential reaches the host, neither from its unit nor from
    # the running process (names only, values never printed).
    local unit_file=/etc/systemd/system/claudia-host.service var pid
    if grep -q '^UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX$' \
        "$unit_file" 2>/dev/null; then
        pass "claudia-host.service unsets every API credential variable (C49)"
    else
        fail "claudia-host.service lacks the C49 UnsetEnvironment= line"
    fi
    pid="$(systemctl show claudia-host.service --property=MainPID --value 2>/dev/null)" || pid=""
    for var in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX; do
        if systemctl show claudia-host.service --property=Environment --value 2>/dev/null \
            | tr ' ' '\n' | grep -q "^${var}="; then
            fail "claudia-host.service sets $var (C49: subscription only)"
        fi
        if [[ -n "$pid" && "$pid" != "0" ]] \
            && tr '\0' '\n' <"/proc/${pid}/environ" 2>/dev/null | grep -q "^${var}="; then
            fail "the running Claudia host has $var in its environment (C49)"
        fi
    done

    # C58 / ADR 0039: the host must sit in its own leaf cgroup (<unit>/host), so
    # each run's sibling cgroup can be killed whole.
    local host_cgroup=""
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        host_cgroup="$(cat "/proc/${pid}/cgroup" 2>/dev/null)" || host_cgroup=""
    fi
    if [[ "$host_cgroup" == *"/claudia-host.service/host" ]]; then
        pass "the Claudia host runs in the claudia-host.service/host cgroup (C58)"
    else
        fail "the Claudia host is not in a .../claudia-host.service/host cgroup (C58, ADR 0039)"
    fi

    # File + directory owners and modes (C45, C47, C50, C53, S-C1 S1).
    check_owner_mode /etc/preview-dashboard/claudia.token root:pdash-claudiatok 640
    check_owner_mode /etc/preview-dashboard/totp.secret root:pdash-totp 640
    check_owner_mode /etc/preview-dashboard/claudia-settings.json root:root 644
    check_owner_mode /etc/preview-dashboard/claudia-mcp.json root:root 644
    check_owner_mode /var/lib/claudia-kb root:pdash-kb 750
    check_owner_mode /var/lib/claudia-host root:root 700
    check_owner_mode /var/lib/preview-dashboard/claudia pdash-admin:pdash 700
    # The viewer's one readable Claudia dir (M5b's pending-approvals snapshot):
    # admin-written, group pdash (the viewer's Group=) read-only, never masked.
    check_owner_mode /var/lib/preview-dashboard/claudia-view pdash-admin:pdash 750
    check_owner_mode /opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook root:root 755

    # deploy-5: exact membership, primary-group users included. pdash-totp
    # and pdash-claudiatok: the admin only (it alone reads the secret and
    # verifies the token); pdash-kb: nobody (only the viewer UNIT holds it).
    check_group_members pdash-totp pdash-admin
    check_group_members pdash-claudiatok pdash-admin
    check_group_members pdash-kb ""
    # The step-up state lives in the admin-only claudia/ dir (masked from
    # the viewer, findmnt-checked below); its owner + 0600 mode stay checked.
    check_owner_only_mode /var/lib/preview-dashboard/claudia/stepup-state.json pdash-admin 600
    check_owner_only_mode /var/lib/preview-dashboard/claudia/stepup-state.lock pdash-admin 600
    # The pre-F-C2b-3 location must be gone (the admin migrates it at start;
    # both present = it refuses every code until the stale one is removed).
    if [[ -e /var/lib/preview-dashboard/stepup-state.json || -e /var/lib/preview-dashboard/stepup-state.lock ]]; then
        fail "old step-up state still in the data dir (restart the admin to migrate it; remove the stale copy if both exist)"
    else
        pass "no step-up state at the old data-dir path"
    fi
    if runuser -u pdash-notify -- test -r /etc/preview-dashboard/totp.secret 2>/dev/null; then
        fail "pdash-notify CAN read totp.secret (C47)"
    else
        pass "pdash-notify cannot read totp.secret"
    fi

    # C57 / S-C1 S1, S2: inside the viewer's own mount namespace, with its
    # unit's groups: the KB is readable and read-only; the admin-only
    # Claudia DB dir and both Claudia secrets are not readable at all.
    if ! have nsenter; then
        fail "nsenter is not installed; cannot verify the viewer's Claudia confinement"
        return
    fi
    local vpid
    vpid="$(systemctl show preview-dashboard-viewer.service --property=MainPID --value 2>/dev/null)" || vpid=""
    if [[ -z "$vpid" || "$vpid" == "0" ]]; then
        fail "preview-dashboard-viewer.service has no MainPID; cannot check its Claudia confinement"
        return
    fi
    local as_viewer=(nsenter --mount="/proc/${vpid}/ns/mnt" -- runuser -u pdash-viewer -g pdash -G pdash-kb --)
    if "${as_viewer[@]}" test -r /var/lib/claudia-kb 2>/dev/null; then
        pass "the viewer can read the knowledge base (C57)"
    else
        fail "the viewer cannot read /var/lib/claudia-kb (ReadOnlyPaths/pdash-kb)"
    fi
    if "${as_viewer[@]}" test -r /var/lib/preview-dashboard/claudia-view 2>/dev/null; then
        pass "the viewer can read the pending-approvals snapshot dir (claudia-view)"
    else
        fail "the viewer cannot read /var/lib/preview-dashboard/claudia-view (masked or wrong mode?)"
    fi
    # deploy-5: `test -w` proves nothing here (the KB is 0750, no group write
    # bit either way); the viewer namespace's own mount table must show the
    # filesystem holding the KB mounted read-only (C57, ReadOnlyPaths=).
    if ! have findmnt; then
        fail "findmnt is not installed; cannot verify the viewer's Claudia mounts"
        return
    fi
    local opts
    opts="$(findmnt --task "$vpid" -rn -o OPTIONS -T /var/lib/claudia-kb 2>/dev/null)" || opts=""
    if [[ ",${opts}," == *",ro,"* ]]; then
        pass "the knowledge base is mounted read-only in the viewer's namespace (C57)"
    else
        fail "the knowledge base is not read-only in the viewer's namespace" \
            "(options '${opts:-?}'; ReadOnlyPaths= missing?)"
    fi
    local path
    for path in /var/lib/preview-dashboard/claudia /etc/preview-dashboard/totp.secret \
        /etc/preview-dashboard/claudia.token; do
        if "${as_viewer[@]}" test -r "$path" 2>/dev/null; then
            fail "the viewer CAN read $path (InaccessiblePaths not effective)"
        else
            pass "the viewer cannot read $path"
        fi
    done
    # deploy-3: `test -r` passes on the modes alone, so also prove each mask
    # is still MOUNTED in the viewer's namespace (a "-" path absent at viewer
    # start, or a file renamed over since, has none).
    for path in /var/lib/preview-dashboard/claudia /var/lib/preview-dashboard/voice \
        /var/lib/claudia-host /etc/preview-dashboard/totp.secret \
        /etc/preview-dashboard/claudia.token; do
        if findmnt --task "$vpid" -rn -M "$path" >/dev/null 2>&1; then
            pass "the viewer's mask on $path is mounted"
        else
            fail "the viewer's mask on $path is not mounted -- run:" \
                "systemctl restart preview-dashboard-viewer (after creating or rotating it)"
        fi
    done
}

# --- F-CL6 (C46, ADR 0043): dashboard Approve/Deny, only while active --------
# (claudia_enabled and claudia_dashboard_decisions, as check-config reports).
# Warns when the feature is on but the units are not wired for it (an old
# unit file: re-run install.sh); fails on a wrong token mode, an extra group
# member, or a viewer that cannot reach the admin socket in its namespace.
check_dashboard_decisions() {
    local config_json="$1" active snapshot_set
    active="$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("claudia_dashboard_decisions", False))' \
        <<<"$config_json" 2>/dev/null)" || active="False"
    if [[ "$active" != "True" ]]; then
        skip "dashboard decisions are not active (Claudia off or claudia_dashboard_decisions = false)"
        return
    fi
    snapshot_set="$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("claudia_approvals_snapshot_set", False))' \
        <<<"$config_json" 2>/dev/null)" || snapshot_set="False"
    if [[ "$snapshot_set" != "True" ]]; then
        warn "dashboard decisions are on but claudia_approvals_snapshot is unset: the panel shows no Approve/Deny"
    fi

    check_owner_mode /etc/preview-dashboard/viewer.token root:pdash-viewtok 640
    # Only the admin (verifier) is a member; the viewer holds it via its unit.
    check_group_members pdash-viewtok pdash-admin

    local viewer_unit=/etc/systemd/system/preview-dashboard-viewer.service
    local admin_unit=/etc/systemd/system/preview-dashboard-admin.service
    # The static unit keeps the L1 mask; the Claudia drop-in lifts it (F-CL6).
    local dropin=/etc/systemd/system/preview-dashboard-viewer.service.d/claudia-decisions.conf
    if grep -q -- '--token-group viewer=pdash-viewtok' "$viewer_unit" 2>/dev/null \
        && grep -q '^SupplementaryGroups=.*pdash-viewtok' "$viewer_unit" 2>/dev/null \
        && grep -q '^InaccessiblePaths=.*/run/preview-dashboard' "$viewer_unit" 2>/dev/null \
        && [[ -r "$dropin" ]] \
        && ! grep -q '^InaccessiblePaths=.*/run/preview-dashboard' "$dropin" 2>/dev/null; then
        pass "the viewer unit and its Claudia drop-in are wired for dashboard decisions"
    else
        warn "dashboard decisions are on but $viewer_unit / $dropin are not wired for them (re-run install.sh)"
    fi
    if grep -q -- '--viewer-peer-uid' "$admin_unit" 2>/dev/null \
        && grep -q -- '--token-group viewer=pdash-viewtok' "$admin_unit" 2>/dev/null; then
        pass "the admin unit is wired for dashboard decisions"
    else
        warn "dashboard decisions are on but $admin_unit is not wired for them (re-run install.sh)"
    fi

    # Socket access from inside the viewer's own namespace, with its unit's groups.
    if ! have nsenter; then
        fail "nsenter is not installed; cannot verify the viewer's admin-socket access"
        return
    fi
    local vpid
    vpid="$(systemctl show preview-dashboard-viewer.service --property=MainPID --value 2>/dev/null)" || vpid=""
    if [[ -z "$vpid" || "$vpid" == "0" ]]; then
        fail "preview-dashboard-viewer.service has no MainPID; cannot check its admin-socket access"
        return
    fi
    local as_viewer=(nsenter --mount="/proc/${vpid}/ns/mnt" -- runuser -u pdash-viewer -g pdash -G pdash-viewtok --)
    if "${as_viewer[@]}" test -w /run/preview-dashboard/admin.sock 2>/dev/null; then
        pass "the viewer can open the admin socket in its namespace (dashboard decisions)"
    else
        fail "the viewer cannot open /run/preview-dashboard/admin.sock in its namespace (masked? restart the viewer)"
    fi
    if "${as_viewer[@]}" test -r /etc/preview-dashboard/viewer.token 2>/dev/null; then
        pass "the viewer can read viewer.token (pdash-viewtok)"
    else
        fail "the viewer cannot read /etc/preview-dashboard/viewer.token"
    fi
    if "${as_viewer[@]}" test -r /etc/preview-dashboard/admin.token 2>/dev/null; then
        fail "the viewer CAN read admin.token (InaccessiblePaths not effective)"
    else
        pass "the viewer still cannot read admin.token"
    fi

    # Token scope (C4/C46): the viewer token reaches only /v1/viewer/*, from
    # pdash-viewer. An empty body is refused (400) after auth: nothing decided.
    local viewer_tok=/etc/preview-dashboard/viewer.token code
    if ! have curl || ! have runuser || [[ ! -r "$viewer_tok" ]]; then
        fail "curl, runuser or viewer.token missing; cannot check the viewer token's scope"
        return
    fi
    code="$(probe_admin_socket pdash-viewer "$viewer_tok" POST \
        /v1/viewer/approvals/00000000000000000000000000/decision)"
    if [[ "$code" == "400" ]]; then
        pass "pdash-viewer with the viewer token reaches /v1/viewer/* (control, 400 empty body)"
    else
        fail "pdash-viewer with the viewer token got HTTP $code on /v1/viewer/* (expected 400)"
    fi
    code="$(probe_admin_socket root "$viewer_tok" GET /v1/health)"
    if [[ "$code" == "403" ]]; then
        pass "an admin route refuses the viewer token (403, from an allowed uid)"
    else
        fail "/v1/health returned HTTP $code for the viewer token as root (expected 403)"
    fi
}

# deploy-5: group $1's members (member list + users whose primary group it
# is), sorted and comma-joined, must equal $2 ("" = no members).
check_group_members() {
    local group="$1" expect="$2" line gid members
    if ! line="$(getent group "$group")"; then
        fail "group $group does not exist"
        return
    fi
    gid="$(cut -d: -f3 <<<"$line")"
    members="$({
        cut -d: -f4 <<<"$line" | tr ',' '\n'
        getent passwd | awk -F: -v g="$gid" '$4 == g { print $1 }'
    } | sed '/^$/d' | sort -u | paste -sd, -)" || members="?"
    if [[ "$members" == "$expect" ]]; then
        pass "group $group has exactly the expected members ('${expect}')"
    else
        fail "group $group members are '${members}' (expected exactly '${expect}')"
    fi
}

# owner (user only) + mode of $1 must equal $2 and $3; absent is fine (the
# file appears with the first step-up use).
check_owner_only_mode() {
    local path="$1" expect_owner="$2" expect_mode="$3" got
    if [[ ! -e "$path" ]]; then
        skip "$path does not exist yet"
        return
    fi
    got="$(stat -c '%U %a' -- "$path" 2>/dev/null)" || got=""
    if [[ "$got" == "$expect_owner $expect_mode" ]]; then
        pass "$path is owned by $expect_owner, mode $expect_mode"
    else
        fail "$path is '${got:-?}' (expected owner $expect_owner, mode $expect_mode)"
    fi
}

# Config booleans from the check-config summary ("False" when the key is absent).
config_flag() {
    python3 -c 'import json, sys; print(json.load(sys.stdin).get(sys.argv[1], False))' "$2" \
        <<<"$1" 2>/dev/null || echo "False"
}

# --- F-CL4 / C61 / C62: voice + photo input switches and the whisper install --
# Read-only. The pins are checked whenever /opt/claudia-whisper exists; a
# missing or mismatched install only warns (the host turns voice input off
# itself and alerts). Both switches default to on; with Claudia off they do nothing.
check_media_input() {
    local config_json="$1" claudia voice photo dir=/opt/claudia-whisper
    claudia="$(config_flag "$config_json" claudia_enabled)"
    voice="$(config_flag "$config_json" claudia_voice_input_enabled)"
    photo="$(config_flag "$config_json" claudia_photo_input_enabled)"

    local whisper_ok=0 rec="$dir/whisper.sha256" rec_model rec_bin
    if [[ -e "$dir" ]]; then
        rec_model="$(sed -n 's/^\([0-9a-f]\{64\}\)  model$/\1/p' "$rec" 2>/dev/null)" || rec_model=""
        rec_bin="$(sed -n 's/^\([0-9a-f]\{64\}\)  binary$/\1/p' "$rec" 2>/dev/null)" || rec_bin=""
        if [[ -n "$rec_model" && -n "$rec_bin" \
            && "$(sha256sum -- "$dir/models/ggml-base.bin" 2>/dev/null | cut -d' ' -f1)" == "$rec_model" \
            && "$(sha256sum -- "$dir/bin/whisper-cli" 2>/dev/null | cut -d' ' -f1)" == "$rec_bin" \
            && "$(sed -n 's/^\([0-9a-f]\{64\}\)  model$/\1/p' /opt/preview-dashboard/deploy/claudia/whisper.sha256 2>/dev/null)" == "$rec_model" ]]; then
            whisper_ok=1
            pass "$dir matches its recorded hashes and the pinned model (C62)"
        else
            fail "$dir does not match its recorded hashes or the pinned model -- re-run: install.sh --whisper (C62)"
        fi
        check_owner_mode "$dir" root:root 755
        check_owner_mode "$dir/bin/whisper-cli" root:root 755
        check_owner_mode "$dir/models/ggml-base.bin" root:root 644
    else
        skip "$dir does not exist (voice-note transcription not installed)"
    fi

    # Both switches default to on (owner 2026-11-09): with Claudia off they do nothing.
    if [[ "$claudia" != "True" ]]; then
        skip "voice/photo input switches act only with claudia_enabled (currently off)"
        return
    fi
    if [[ "$voice" == "True" && ! -e "$dir" ]]; then
        warn "claudia_voice_input_enabled = true (the default) but $dir is missing:" \
            "voice notes are NOT transcribed; the host turns voice input off, alerts once and" \
            "answers voice notes with a fixed reply. Install: install.sh --claudia --whisper," \
            "or set claudia_voice_input_enabled = false"
    elif [[ "$voice" == "True" && "$whisper_ok" -ne 1 ]]; then
        warn "claudia_voice_input_enabled = true but $dir does not match its pins:" \
            "the host turns voice input off (re-run install.sh --claudia --whisper)"
    fi
    # Voice notes are decoded with soundfile/numpy (the claudia-voice extra,
    # which install.sh --whisper installs); without them every note fails.
    if [[ "$voice" == "True" ]]; then
        if "$VENV_PYTHON" -c 'import numpy, soundfile' >/dev/null 2>&1; then
            pass "soundfile and numpy import in the host venv (voice-note decoding)"
        else
            warn "claudia_voice_input_enabled = true but soundfile/numpy do not import in" \
                "$VENV_PYTHON: voice notes cannot be decoded (re-run install.sh --claudia --whisper)"
        fi
    fi
    if [[ "$photo" == "True" ]]; then
        pass "photo input on (read-only photo turns unless claudia_photo_turn_tools = \"full\")"
    fi
}

# --- C1: Funnel (public exposure) must stay off ----------------------------
check_funnel_off() {
    if ! have tailscale; then
        fail "tailscale is not installed"
        return
    fi
    local out
    out="$(tailscale funnel status 2>&1)" || true
    if grep -qi 'funnel on' <<<"$out"; then
        fail "tailscale funnel is ON: $out"
    else
        pass "tailscale funnel is off"
    fi
}

main() {
    local config_json host
    config_json="$(read_config_summary)"
    host="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["allowed_hosts"][0])' \
        <<<"$config_json")" || {
        echo "error: could not read allowed_hosts from the config summary:" >&2
        echo "$config_json" >&2
        exit 1
    }
    echo "== preview-dashboard live verification (host: $host) =="
    echo

    check_nft_table
    check_nobody_refused "$host"
    check_no_identity_403 "$host"
    check_services_fresh_and_active
    check_viewer_confinement
    check_systemd_analyze_security
    check_funnel_off
    check_notifier "$config_json"
    check_claudia "$config_json"
    check_dashboard_decisions "$config_json"
    check_media_input "$config_json"

    echo
    if [[ "$FAILURES" -gt 0 ]]; then
        echo "== $FAILURES check(s) FAILED =="
        exit 1
    fi
    echo "== all checks passed =="
}

main "$@"
