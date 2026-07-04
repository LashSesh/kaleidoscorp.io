#!/usr/bin/env bash
# Manual check for ssk-ipc's Unix peer-credential authentication
# (crates/ssk-ipc/src/auth.rs): a client connecting as a *different* OS user
# than the daemon must be rejected. This cannot be exercised in a standard
# single-user CI container (there is no second user to switch to), so it is
# a documented, scripted manual check instead of a false claim of automated
# coverage — see the `#[ignore]`d `different_user_is_rejected` test in
# crates/ssk-ipc/src/auth.rs.
#
# Usage:
#   sudo ./scripts/manual_peer_cred_test.sh <second-username>
#
# Requires: root (to run `sudo -u <second-username>`), a second real user
# account on the machine, and a workspace build (`cargo build --workspace`).

set -euo pipefail

SECOND_USER="${1:?usage: manual_peer_cred_test.sh <second-username>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$(mktemp -d)"
SSKD_BIN="$REPO_ROOT/target/debug/sskd"
SSK_BIN="$REPO_ROOT/target/debug/ssk"

if [[ ! -x "$SSKD_BIN" || ! -x "$SSK_BIN" ]]; then
    echo "Building workspace (debug) first..." >&2
    (cd "$REPO_ROOT" && cargo build --workspace)
fi

echo "Starting sskd as $(whoami) with state dir $STATE_DIR ..." >&2
SSK_STATE_DIR="$STATE_DIR" "$SSKD_BIN" &
SSKD_PID=$!
trap 'kill "$SSKD_PID" 2>/dev/null || true; rm -rf "$STATE_DIR"' EXIT

for _ in $(seq 1 50); do
    [[ -S "$STATE_DIR/sskd.sock" ]] && break
    sleep 0.1
done
if [[ ! -S "$STATE_DIR/sskd.sock" ]]; then
    echo "FAIL: sskd did not create its socket in time" >&2
    exit 1
fi

echo "Connecting as $(whoami) (same user) — must succeed ..." >&2
if SSK_STATE_DIR="$STATE_DIR" "$SSK_BIN" --json status >/dev/null; then
    echo "OK: same-user connection accepted." >&2
else
    echo "FAIL: same-user connection was rejected (unexpected)." >&2
    exit 1
fi

echo "Connecting as $SECOND_USER (different user) — must be rejected ..." >&2
if sudo -u "$SECOND_USER" env SSK_STATE_DIR="$STATE_DIR" "$SSK_BIN" --json status >/tmp/manual_peer_cred_out.json 2>&1; then
    echo "FAIL: different-user connection was accepted (security regression!)." >&2
    cat /tmp/manual_peer_cred_out.json >&2
    exit 1
fi

if grep -q "IPC_PEER_REJECTED" /tmp/manual_peer_cred_out.json; then
    echo "OK: different-user connection was rejected with IPC_PEER_REJECTED." >&2
    exit 0
fi

echo "FAIL: different-user connection failed, but not with the expected IPC_PEER_REJECTED code." >&2
cat /tmp/manual_peer_cred_out.json >&2
exit 1
