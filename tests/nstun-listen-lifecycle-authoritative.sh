#!/bin/sh
set -eu

# Linux/root integration fixture. It uses only a local LISTEN socket and the
# disposable network namespace in the config; it never contacts an external
# service. Override NSJAIL_BIN, CONFIG, PORT, COUNT, and TIMEOUT_SECONDS.
NSJAIL_BIN=${NSJAIL_BIN:-./nsjail}
CONFIG=${CONFIG:-tests/nstun-listen-lifecycle.cfg}
PORT=${PORT:-38080}
COUNT=${COUNT:-10}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-3}
LOG=${LOG:-${TMPDIR:-/tmp}/nsjail-nstun-lifecycle.parent.log}
TMP_CFG=$(mktemp "${TMPDIR:-/tmp}/nstun-config.XXXXXX")
RAW=${RAW:-${TMPDIR:-/tmp}/nsjail-nstun-lifecycle.raw}
mkdir -p "$RAW"

cleanup() {
	set +e
	if [ "${NSJAIL_PID:-}" != "" ] && kill -0 "$NSJAIL_PID" 2>/dev/null; then
		kill -TERM "$NSJAIL_PID" 2>/dev/null
		for _ in $(seq 1 40); do
			kill -0 "$NSJAIL_PID" 2>/dev/null || break
			sleep 0.05
		done
		kill -KILL "$NSJAIL_PID" 2>/dev/null
		wait "$NSJAIL_PID" 2>/dev/null
	fi
	rm -f "$TMP_CFG"
}
trap cleanup EXIT INT TERM

sed "s/^port: .*/port: ${PORT}/" "$CONFIG" >"$TMP_CFG"
: >"$LOG"
"$NSJAIL_BIN" -C "$TMP_CFG" >"$LOG" 2>&1 &
NSJAIL_PID=$!

for _ in $(seq 1 100); do
	if ss -H -ltn 2>/dev/null | awk -v p=":${PORT}" '$4 ~ p"$" {ok=1} END {exit !ok}'; then
		break
	fi
	sleep 0.05
done
kill -0 "$NSJAIL_PID" 2>/dev/null || {
	echo "nsjail exited before readiness" >&2
	exit 1
}

counts() {
	pid=$1
	tasks=$(find "/proc/$pid/task" -mindepth 1 -maxdepth 1 -type d | wc -l)
	fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
	threads=$(awk '/^Threads:/{print $2}' "/proc/$pid/status")
	printf '%s %s %s\n' "$tasks" "$fds" "$threads"
}

targets() {
	pid=$1
	for fd in /proc/$pid/fd/*; do
		[ -e "$fd" ] || continue
		readlink "$fd" 2>/dev/null || true
	done | sort
}

snapshot() {
	label=$1
	counts "$NSJAIL_PID" >"$RAW/$label.counts"
	targets "$NSJAIL_PID" >"$RAW/$label.targets"
	printf '%s\t%s\n' "$label" "$(cat "$RAW/$label.counts")" >&2
}

client_once() {
	python3 - "$PORT" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    s.sendall(b"nstun-lifecycle\n")
    try:
        s.recv(1)
    except OSError:
        pass
finally:
    s.close()
PY
}

snapshot idle
baseline=$(cat "$RAW/idle.counts")
cp "$RAW/idle.counts" "$RAW/baseline.counts"
cp "$RAW/idle.targets" "$RAW/baseline.targets"
echo "baseline=$baseline"

for i in $(seq 1 "$COUNT"); do
	client_once || true
	deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
	while [ "$(grep -Ec 'pid=.*(exited|terminated with signal)' "$LOG" || true)" -lt "$i" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || {
			echo "child $i was not reaped" >&2
			exit 1
		}
		sleep 0.05
	done
	# The exit log is emitted before removeProc() performs NSTUN teardown.
	# Poll the independent parent readbacks until the join/close completes.
	while :; do
		counts "$NSJAIL_PID" >"$RAW/post-$i.candidate.counts"
		targets "$NSJAIL_PID" >"$RAW/post-$i.candidate.targets"
		if cmp -s "$RAW/baseline.counts" "$RAW/post-$i.candidate.counts" &&
			cmp -s "$RAW/baseline.targets" "$RAW/post-$i.candidate.targets"; then
			cp "$RAW/post-$i.candidate.counts" "$RAW/post-$i.counts"
			cp "$RAW/post-$i.candidate.targets" "$RAW/post-$i.targets"
			break
		fi
		[ "$(date +%s)" -lt "$deadline" ] || {
			echo "parent resources did not return to baseline after child $i" >&2
			exit 1
		}
		sleep 0.05
	done
	current=$(cat "$RAW/post-$i.counts")
	echo "post-$i=$current"
	[ "$current" = "$baseline" ] || {
		echo "resource count changed after child $i: $baseline -> $current" >&2
		exit 1
	}
	diff -u "$RAW/baseline.targets" "$RAW/post-$i.targets"
done

if grep -Eq '^(/net/tun|anon_inode:\[eventpoll\])$' "$RAW/baseline.targets" "$RAW/post-$COUNT.targets"; then
	echo "unexpected NSTUN-owned descriptor remained in the parent" >&2
	exit 1
fi

echo "PASS: ${COUNT} NSTUN LISTEN children returned parent resources to baseline"
