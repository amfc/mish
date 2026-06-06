#!/usr/bin/env bash
# End-to-end test of the builtin (russh) SSH bootstrap against a *real* sshd.
#
# The in-crate tests cover the bootstrap parsers, the bounded MISH CONNECT
# scanner, host-key verdicts, and shell-quote injection-resistance, and
# `bootstrap_e2e.rs` drives the full session over the `--local` path. What none
# of those exercise is the actual russh client talking to a real SSH server —
# that needs an sshd and working key auth, which CI usually lacks. This script
# provisions exactly that against localhost (a throwaway key, a scoped
# authorized_keys line, and a private ssh-agent), runs the real `mish-client`
# through both transports, and asserts a command's output traverses the session.
# Everything it adds is removed on exit.
#
#   ./scripts/test-builtin-bootstrap.sh            # against 127.0.0.1
#   MISH_E2E_HOST=otherhost ./scripts/test-builtin-bootstrap.sh
#
# Requires: a running sshd reachable from this account, ssh-keygen/ssh-agent,
# python3 (for a PTY), and cargo. Exits 0 only if every check passes.
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root (script lives in scripts/)

HOST="${MISH_E2E_HOST:-127.0.0.1}"
PORT="${MISH_E2E_SSH_PORT:-22}"
USER_AT_HOST="$(whoami)@${HOST}"

echo "==> Building mish-client / mish-server"
cargo build -q -p mosh --bins
CLIENT="$PWD/target/debug/mish-client"
SERVER="$PWD/target/debug/mish-server"

# --- provisioning (all cleaned up on EXIT) ------------------------------------
TMP="$(mktemp -d /tmp/mish-e2e.XXXXXX)"
KEY="$TMP/id_ed25519"
MARK="mish-e2e-$$-$(date +%s 2>/dev/null || echo now)"
AGENT_PID=""
AK_TOUCHED=0

cleanup() {
  # Remove only the authorized_keys line we added (matched by its unique marker).
  if [ "$AK_TOUCHED" = 1 ] && [ -f "$HOME/.ssh/authorized_keys" ]; then
    grep -v "$MARK" "$HOME/.ssh/authorized_keys" > "$TMP/ak.clean" 2>/dev/null || true
    cp "$TMP/ak.clean" "$HOME/.ssh/authorized_keys" 2>/dev/null || true
  fi
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "==> Provisioning a throwaway key + agent + authorized_keys entry"
ssh-keygen -t ed25519 -N "" -f "$KEY" -C "$MARK" -q
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys"
cat "$KEY.pub" >> "$HOME/.ssh/authorized_keys"
AK_TOUCHED=1
eval "$(ssh-agent -s)" >/dev/null
ssh-add "$KEY" 2>/dev/null

# PTY driver: mish-client needs a real terminal; feed a command and look for
# its output coming back through the session.
cat > "$TMP/drive.py" <<'PY'
import os, pty, sys, time, select, struct, fcntl, termios
# $MISH_CHILD_PATH (if set) becomes the client's PATH — lets a caller hide
# `ssh` from the client without hiding python3/etc. from this driver.
cp = os.environ.get("MISH_CHILD_PATH")
if cp is not None:
    os.environ["PATH"] = cp
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
out = b""
def seen(tok): return tok in out.replace(b"\x00", b"")
def pump(timeout, until=None):
    # Read for up to `timeout`s, returning early once `until` (if given) appears.
    global out; end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if fd in r:
            try: d = os.read(fd, 4096)
            except OSError: return
            if not d: return
            out += d
            if until is not None and seen(until): return
pump(4.0)                                # let the bootstrap + shell prompt settle
# The marker is a *computed* value: we type `OUT_$((21+21))`, which echoes back
# literally, but only a shell that actually ran it produces `OUT_42`. So matching
# `OUT_42` proves the session executed the command, not that our input was echoed.
os.write(fd, b"echo OUT_$((21+21))\r")
pump(10.0, until=b"OUT_42")               # poll up to 10s, return as soon as seen
try: os.write(fd, b"exit\r")
except OSError: pass
sys.exit(0 if seen(b"OUT_42") else 1)
PY

PASS=0; FAIL=0
check() {  # check <name> <expect-pass:0|1> <cmd...>
  local name="$1" expect="$2"; shift 2
  if "$@"; then rc=0; else rc=1; fi
  if [ "$rc" = "$expect" ]; then
    echo "  PASS: $name"; PASS=$((PASS+1))
  else
    echo "  FAIL: $name (rc=$rc, expected=$expect)"; FAIL=$((FAIL+1))
  fi
}

echo "==> Running checks against $USER_AT_HOST:$PORT"

# 1. builtin transport carries a command's output end-to-end.
check "builtin transport: command output flows" 0 \
  python3 "$TMP/drive.py" "$CLIENT" --bootstrap=builtin --ssh-port "$PORT" \
    --predict never --server "$SERVER" "$USER_AT_HOST"

# 2. parity: the system ssh transport does the same. We pass non-interactive ssh
#    options (accept-new ≈ the builtin client's trust-on-first-use; BatchMode so a
#    missing key fails fast instead of prompting) so an unknown 127.0.0.1 host key
#    doesn't block the test.
check "ssh transport (parity): command output flows" 0 \
  python3 "$TMP/drive.py" "$CLIENT" --bootstrap=ssh --predict never \
    --ssh "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
    --server "$SERVER" "$USER_AT_HOST"

# 3. auto falls back to builtin when `ssh` is absent from the client's PATH.
check "auto falls back to builtin (no ssh on PATH)" 0 \
  env MISH_CHILD_PATH="$TMP" python3 "$TMP/drive.py" "$CLIENT" --bootstrap=auto \
    --ssh-port "$PORT" --predict never --server "$SERVER" "$USER_AT_HOST"

# 4. wrong user must fail to authenticate (negative test).
check "builtin rejects an unknown user" 1 \
  python3 "$TMP/drive.py" "$CLIENT" --bootstrap=builtin --ssh-port "$PORT" \
    --predict never --server "$SERVER" "nosuchuser_xyz_$$@$HOST"

# A temp ssh_config (via $MISH_SSH_CONFIG) exercising config resolution and
# ProxyJump. `viajump` tunnels through 127.0.0.1 to reach 127.0.0.1 (localhost as
# its own jump host) — enough to drive the whole ProxyJump code path.
cat > "$TMP/ssh_config" <<EOF
Host mishtarget
    HostName $HOST
    User $(whoami)
    Port $PORT
Host viajump
    HostName $HOST
    User $(whoami)
    Port $PORT
    ProxyJump $(whoami)@$HOST:$PORT
EOF

# 5. ~/.ssh/config resolution: connect by alias (HostName/User/Port from config).
check "config alias resolves (HostName/User/Port)" 0 \
  env MISH_SSH_CONFIG="$TMP/ssh_config" python3 "$TMP/drive.py" "$CLIENT" \
    --bootstrap=builtin --predict never --server "$SERVER" "mishtarget"

# 6. ProxyJump: bootstrap tunnels through the jump host, then runs the command.
check "ProxyJump tunnel carries command output" 0 \
  env MISH_SSH_CONFIG="$TMP/ssh_config" python3 "$TMP/drive.py" "$CLIENT" \
    --bootstrap=builtin --predict never --server "$SERVER" "viajump"

# Note: passphrase-protected keys, password, and keyboard-interactive auth are
# interactive (TTY prompts) and covered by the unit tests + code; they aren't
# scripted here.

echo
echo "==> $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
