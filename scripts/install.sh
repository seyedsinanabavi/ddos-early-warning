#!/usr/bin/env bash
# Installs ddos-early-warning as a systemd service on Linux.
#
# Run as root from the repository root or the extracted offline package:
#   sudo ./scripts/install.sh
#
# Safe to re-run. Existing configs and the secrets file are never overwritten.
# The service is enabled but not started on first install, so the operator can
# review the configs first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${BIN_SRC:-$ROOT/bin/ddos-ew}"
BIN_DST="/usr/local/bin/ddos-ew"
CONF_DIR="/etc/ddos-ew"
ENV_FILE="$CONF_DIR/ddos-ew.env"
STATE_DIR="/var/lib/ddos-ew"
SVC_USER="ddos-ew"
UNIT_SRC="$ROOT/deploy/systemd/ddos-ew.service"
UNIT_DST="/etc/systemd/system/ddos-ew.service"
CONFIGS=(collector.yaml detection.yaml alerts.yaml)

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (use sudo)"
command -v systemctl >/dev/null || die "systemd is required"
[[ -x "$BIN_SRC" ]] || die "binary not found or not executable: $BIN_SRC"
[[ -f "$UNIT_SRC" ]] || die "unit file not found: $UNIT_SRC"
for f in "${CONFIGS[@]}"; do
  [[ -f "$ROOT/configs/$f" ]] || die "missing $ROOT/configs/$f"
done

# Service account: system user, no login shell, no home directory.
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  log "created system user $SVC_USER"
fi
# Nginx and haproxy logs are usually readable by the adm group.
if getent group adm >/dev/null; then
  usermod -a -G adm "$SVC_USER"
fi

install -m 0755 -o root -g root "$BIN_SRC" "$BIN_DST"
log "installed $BIN_DST"

install -d -m 0755 -o root -g root "$CONF_DIR"
fresh_config=0
for f in "${CONFIGS[@]}"; do
  if [[ -e "$CONF_DIR/$f" ]]; then
    log "kept existing $CONF_DIR/$f"
  else
    install -m 0644 -o root -g root "$ROOT/configs/$f" "$CONF_DIR/$f"
    log "installed $CONF_DIR/$f"
    fresh_config=1
  fi
done

if [[ ! -e "$ENV_FILE" ]]; then
  install -m 0600 -o root -g root /dev/null "$ENV_FILE"
  cat >"$ENV_FILE" <<'ENVEOF'
# Secrets for webhook channels. Referenced by token_env / secret_env in alerts.yaml.
# Example:
# ALERT_WEBHOOK_TOKEN=replace-me
ENVEOF
  log "created $ENV_FILE (add secrets here; it is readable by root only)"
fi

install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
log "state directory $STATE_DIR is owned by $SVC_USER"

if ! grep -Eq "^[[:space:]]*dir:[[:space:]]*['\"]?$STATE_DIR['\"]?[[:space:]]*$" "$CONF_DIR/collector.yaml"; then
  log "warning: storage.dir in $CONF_DIR/collector.yaml is not $STATE_DIR; the service will use that directory instead"
fi

install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable ddos-ew.service >/dev/null
log "unit installed and enabled"

if systemctl is-active --quiet ddos-ew.service; then
  systemctl restart ddos-ew.service
  log "service restarted with the new binary"
elif [[ $fresh_config -eq 1 ]]; then
  log "next: review $CONF_DIR/*.yaml (log paths, thresholds), then: systemctl start ddos-ew"
else
  log "next: systemctl start ddos-ew"
fi

log "done. Check status with: systemctl status ddos-ew  and  journalctl -u ddos-ew -f"