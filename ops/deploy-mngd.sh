#!/bin/bash
# Install one signed release and keep the previous version for rollback.
#
# Usage (on the server, as root):
#   ops/deploy-mngd.sh --binary /root/incoming/mngd \
#                      --app /root/incoming/app \
#                      --version 1.2.3
#
# The app directory must already contain manifest.json + manifest.sig produced
# by `mng-sign package` on the offline signing machine.
set -euo pipefail

BINARY=""
APP=""
VERSION=""
PUBLIC_KEY="/etc/mng-cloud/update-public.jwk"
APP_ROOT="/var/www/mng-cloud-app"
BIN_PATH="/usr/local/bin/mngd"

usage() {
    sed -n '2,14p' "$0"
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="${2:-}"; shift 2 ;;
        --app) APP="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --public-key) PUBLIC_KEY="${2:-}"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi
if [[ -z "$BINARY" || -z "$APP" || -z "$VERSION" ]]; then
    echo "--binary, --app and --version are required" >&2
    exit 2
fi
if [[ ! "$VERSION" =~ ^[0-9][0-9A-Za-z.+-]{0,63}$ ]]; then
    echo "invalid version: $VERSION" >&2
    exit 2
fi
if [[ ! -x "$BINARY" && ! -f "$BINARY" ]]; then
    echo "binary not found: $BINARY" >&2
    exit 1
fi
if [[ ! -f "$APP/manifest.json" || ! -f "$APP/manifest.sig" || ! -f "$APP/sw.js" ]]; then
    echo "app directory is not a signed release: $APP" >&2
    exit 1
fi

# Optional but strongly recommended: verify the release on the server with the
# public key only. mng-sign never sees the private key at this point.
if command -v mng-sign >/dev/null 2>&1 && [[ -f "$PUBLIC_KEY" ]]; then
    echo "==> verifying signed app"
    mng-sign verify --public-key "$PUBLIC_KEY" --dir "$APP"
else
    echo "WARNING: mng-sign or $PUBLIC_KEY missing; signature not checked locally" >&2
fi

RELEASE="$APP_ROOT/releases/$VERSION"
if [[ -e "$RELEASE" ]]; then
    echo "release already exists: $RELEASE" >&2
    exit 1
fi

echo "==> installing mngd"
install -d -o root -g root -m 0755 "$APP_ROOT/releases"
install -o root -g root -m 0755 "$BINARY" "$BIN_PATH.new"
if [[ -f "$BIN_PATH" ]]; then
    cp -a "$BIN_PATH" "$BIN_PATH.previous"
fi
mv -f "$BIN_PATH.new" "$BIN_PATH"

echo "==> installing immutable app"
install -d -o root -g root -m 0755 "$RELEASE"
cp -a "$APP/." "$RELEASE/"
chown -R root:root "$RELEASE"
chmod -R a-w "$RELEASE"
find "$RELEASE" -type d -exec chmod 0555 {} +
find "$RELEASE" -type f -exec chmod 0444 {} +

PREVIOUS="$(readlink -f "$APP_ROOT/current" 2>/dev/null || true)"
ln -sfn "$RELEASE" "$APP_ROOT/current.new"
mv -Tf "$APP_ROOT/current.new" "$APP_ROOT/current"

echo "==> restarting mngd"
systemctl restart mngd

for _ in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:8090/healthz >/dev/null 2>&1; then
        echo "==> healthy: $VERSION"
        exit 0
    fi
    sleep 0.5
done

echo "health check failed; rolling back" >&2
if [[ -n "$PREVIOUS" && -d "$PREVIOUS" ]]; then
    ln -sfn "$PREVIOUS" "$APP_ROOT/current.new"
    mv -Tf "$APP_ROOT/current.new" "$APP_ROOT/current"
fi
if [[ -f "$BIN_PATH.previous" ]]; then
    mv -f "$BIN_PATH.previous" "$BIN_PATH"
fi
systemctl restart mngd || true
exit 1
