#!/usr/bin/env bash
# deploy/tailscale/serve.sh — front the viewer with `tailscale serve` and
# verify Funnel stays off (docs/security.md C1, ADR 0002).
#
# Not run by install.sh automatically: `tailscale serve` config lives in
# tailscaled's own state, is per-host, and (per the project plan) enrolling
# the host in the tailnet is an owner action. Run this once, as root, after
# `tailscale up` has been completed for this host.
#
# Usage: sudo deploy/tailscale/serve.sh [--dry-run]

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            echo "usage: $0 [--dry-run]"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

run() {
    echo "+ $*"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        "$@"
    fi
}

# `tailscale serve` on a tailnet where Serve hasn't been turned on by an
# admin can hang instead of erroring (it waits on a state it will never
# reach) — a bare `run` above would leave this script stuck forever with no
# indication why. Wrap with `timeout` and inspect the captured output so a
# disabled-Serve tailnet fails loudly, fast, with the actual fix.
SERVE_TIMEOUT_SECONDS=15

run_serve() {
    echo "+ $*"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        return 0
    fi
    local output
    if ! output="$(timeout "${SERVE_TIMEOUT_SECONDS}s" "$@" 2>&1)"; then
        echo "$output" >&2
        echo "ERROR: '$*' did not complete (timed out after ${SERVE_TIMEOUT_SECONDS}s, or failed)." >&2
        if grep -qi "not enabled" <<<"$output"; then
            echo "Serve is not enabled on your tailnet; ask a tailnet admin to enable it" >&2
            echo "(https://tailscale.com/kb/1312/serve), then re-run this script." >&2
        fi
        exit 1
    fi
    [[ -n "$output" ]] && echo "$output"
}

if ! command -v tailscale >/dev/null 2>&1; then
    echo "tailscale is not installed; install it first (see docs/operations.md)" >&2
    exit 1
fi

if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "run as root (tailscale serve writes tailscaled's root-owned state)" >&2
    exit 1
fi

# Dashboard: tailnet HTTPS 443 -> local viewer port 8787.
run_serve tailscale serve --bg --https=443 http://127.0.0.1:8787
# Preview origin: tailnet HTTPS 8443 -> local preview port 8788 (must stay a
# separate origin from the dashboard, C5 — do not collapse these into one
# `tailscale serve` target).
run_serve tailscale serve --bg --https=8443 http://127.0.0.1:8788

# Funnel (public exposure) must stay off (C1, ADR 0002): `tailscale serve`
# and `tailscale funnel` share config, so a stray `funnel` command anywhere
# on this host would make the dashboard internet-reachable. Fail loudly if
# it's ever on, rather than silently trusting it's still off.
if [[ "$DRY_RUN" -eq 0 ]]; then
    funnel_status="$(tailscale funnel status 2>&1 || true)"
    # Current tailscale prints "(tailnet only)" per served port and
    # "(Funnel on)" for public ones; same check as deploy/check.sh.
    if grep -qi "funnel on" <<<"$funnel_status"; then
        echo "WARNING: 'tailscale funnel status' reports Funnel ON:" >&2
        echo "$funnel_status" >&2
        echo "Run 'tailscale funnel off' before trusting this deployment." >&2
        exit 1
    fi
    echo "funnel: off (confirmed)"

    hostname="$(tailscale status --json 2>/dev/null | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data.get("Self", {}).get("DNSName", "").rstrip("."))
' 2>/dev/null || true)"
    if [[ -n "$hostname" ]]; then
        echo "tailnet hostname: https://${hostname}"
        echo "This name must match allowed_hosts in /etc/preview-dashboard/config.toml"
        echo "(the --host given to deploy/setup-wizard.sh or deploy/install.sh); if it"
        echo "differs, re-run the wizard with this host."
    else
        echo "Could not determine the tailnet hostname automatically;" >&2
        echo "run 'tailscale status' and use the *.ts.net name it reports." >&2
    fi
fi

echo "Next: tag this host tag:pdash (preferably in the Tailscale admin console, Machines),"
echo "merge deploy/tailscale/acl-snippet.json restricting tag:pdash:443,8443 to the"
echo "owner's identity, remove or narrow any allow-all rule (grants are additive),"
echo "then verify with 'tailscale serve status' and from a non-owner device (docs/setup.md)."
