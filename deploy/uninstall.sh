#!/usr/bin/env bash
# deploy/uninstall.sh — stop and remove the preview-dashboard services.
#
# By default keeps all data (the SQLite DB, blobs, config, admin token) and
# the pdash-admin/pdash-viewer accounts and pdash group — only the
# systemd units, nftables rule and /opt checkout are removed, so re-running
# install.sh later picks up where this left off. --purge-data additionally
# removes /var/lib/preview-dashboard, /etc/preview-dashboard and
# /root/outbox, and --purge-users additionally removes the service accounts
# and group.
#
# Usage: sudo deploy/uninstall.sh [--dry-run] [--purge-data] [--purge-users]
set -euo pipefail

SERVICE_GROUP="pdash"
ADMIN_USER="pdash-admin"
VIEWER_USER="pdash-viewer"
NOTIFY_USER="pdash-notify"
NOTIFY_TOK_GROUP="pdash-notifytok"
# Claudia (M9, ADR 0036): removed unconditionally like the notifier.
CLAUDIA_GROUPS=(pdash-claudiatok pdash-totp pdash-kb)

DRY_RUN=0
PURGE_DATA=0
PURGE_USERS=0
PREFIX="${PDASH_PREFIX:-}"

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --purge-data) PURGE_DATA=1 ;;
        --purge-users) PURGE_USERS=1 ;;
        -h | --help)
            echo "usage: $0 [--dry-run] [--purge-data] [--purge-users]"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (or pass --dry-run)" >&2
    exit 1
fi

OPT_DIR="${PREFIX}/opt/preview-dashboard"
ETC_DIR="${PREFIX}/etc/preview-dashboard"
VAR_DIR="${PREFIX}/var/lib/preview-dashboard"
SYSTEMD_DIR="${PREFIX}/etc/systemd/system"
OUTBOX_DIR="${PREFIX}/root/outbox"
KB_DIR="${PREFIX}/var/lib/claudia-kb"
HOST_STATE_DIR="${PREFIX}/var/lib/claudia-host"

log() { echo "== $*"; }
run() {
    echo "+ $*"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        "$@"
    fi
}

log "stop + disable services"
# Claudia first: her runs use the admin API (the host's KillMode stops them).
run systemctl disable --now claudia-gardener.timer || true
run systemctl disable --now claudia-host.service || true
run systemctl stop claudia-gardener.service || true
run systemctl disable --now preview-dashboard-purge.timer || true
run systemctl disable --now preview-dashboard-admin.service || true
run systemctl disable --now preview-dashboard-viewer.service || true
run systemctl disable --now preview-dashboard-notifier.service || true
run systemctl stop preview-dashboard-purge.service || true
run systemctl disable --now preview-dashboard-firewall.service || true

log "remove systemd units"
for unit in preview-dashboard-admin.service preview-dashboard-viewer.service \
    preview-dashboard-purge.service preview-dashboard-purge.timer \
    preview-dashboard-firewall.service preview-dashboard-notifier.service \
    claudia-host.service claudia-gardener.service claudia-gardener.timer; do
    run rm -f "$SYSTEMD_DIR/$unit"
done
run systemctl daemon-reload
run systemctl reset-failed || true

log "remove loopback firewall table"
run nft delete table inet preview_dashboard || true

log "remove installed code"
run rm -rf "$OPT_DIR"

if [[ "$PURGE_DATA" -eq 1 ]]; then
    log "PURGING DATA (--purge-data): DB, blobs, config, token, outbox, Claudia KB + state"
    run rm -rf "$VAR_DIR"
    run rm -rf "$ETC_DIR"
    run rm -rf "$OUTBOX_DIR"
    run rm -rf "$KB_DIR"
    run rm -rf "$HOST_STATE_DIR"
else
    log "keeping data: $VAR_DIR, $ETC_DIR, $OUTBOX_DIR, $KB_DIR, $HOST_STATE_DIR (pass --purge-data to remove)"
fi

if [[ "$PURGE_USERS" -eq 1 ]]; then
    log "PURGING USERS (--purge-users): $ADMIN_USER, $VIEWER_USER, $NOTIFY_USER, $SERVICE_GROUP, $NOTIFY_TOK_GROUP"
    run userdel "$VIEWER_USER" || true
    run userdel "$NOTIFY_USER" || true
    run userdel "$ADMIN_USER" || true
    run groupdel "$NOTIFY_TOK_GROUP" || true
    for group in "${CLAUDIA_GROUPS[@]}"; do
        run groupdel "$group" || true
    done
    run groupdel "$SERVICE_GROUP" || true
else
    log "keeping users: $ADMIN_USER, $VIEWER_USER, $NOTIFY_USER, $SERVICE_GROUP, $NOTIFY_TOK_GROUP" \
        "(pass --purge-users to remove)"
fi

log "done"
