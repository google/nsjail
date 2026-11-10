#!/bin/sh
set -eu

# Local-only Linux/root integration fixture. The extra loopback address lets us
# verify that an IPv6 wildcard listener does not widen a ::1-only REDIRECT.
NSJAIL_BIN=${NSJAIL_BIN:-./nsjail}
CONFIG=${CONFIG:-tests/dns_http_host_to_guest.cfg}
LOG=${LOG:-${TMPDIR:-/tmp}/nsjail-host-to-guest.log}
MISMATCH_IP6=${MISMATCH_IP6:-2001:db8::1}
ADDED_IP6=false

cleanup() {
	set +e
	if [ "${NSJAIL_PID:-}" != "" ] && kill -0 "$NSJAIL_PID" 2>/dev/null; then
		kill -TERM "$NSJAIL_PID" 2>/dev/null
		wait "$NSJAIL_PID" 2>/dev/null
	fi
	if [ "$ADDED_IP6" = true ]; then
		ip -6 addr del "$MISMATCH_IP6/128" dev lo 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM

if ! ip -6 addr show dev lo | grep -Fq "$MISMATCH_IP6/128"; then
	ip -6 addr add "$MISMATCH_IP6/128" dev lo
	ADDED_IP6=true
fi

: >"$LOG"
"$NSJAIL_BIN" --config "$CONFIG" --cwd "$(pwd)" -q -t 15 >"$LOG" 2>&1 &
NSJAIL_PID=$!

python3 - "$MISMATCH_IP6" <<'PY'
import socket
import sys
import time

mismatch_ip6 = sys.argv[1]


def exchange_http(family, address, port):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((address, port))
        sock.sendall(b"GET / HTTP/1.0\r\nHost: nstun\r\n\r\n")
        return sock.recv(4096)
    finally:
        sock.close()


def expect_http(family, address, port):
    deadline = time.monotonic() + 5
    while True:
        try:
            response = exchange_http(family, address, port)
            if response.startswith(b"HTTP/") and b" 200 " in response.split(b"\r\n", 1)[0]:
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(f"no HTTP response from {address}:{port}")
        time.sleep(0.05)


def expect_no_http(family, address, port):
    try:
        response = exchange_http(family, address, port)
    except OSError:
        return
    if response:
        raise AssertionError(f"unexpected TCP payload from {address}:{port}")


def send_udp(family, address, port, payload):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        for _ in range(3):
            sock.sendto(payload, (address, port))
            time.sleep(0.05)
    finally:
        sock.close()


# Existing wildcard behavior remains available.
expect_http(socket.AF_INET, "127.0.0.1", 8080)
expect_http(socket.AF_INET6, "::1", 8080)

# Owner match succeeds despite the preceding broad ALLOW; owner mismatch fails.
expect_http(socket.AF_INET, "127.0.0.1", 8081)
expect_no_http(socket.AF_INET, "127.0.0.2", 8081)
expect_http(socket.AF_INET6, "::1", 8081)
expect_no_http(socket.AF_INET6, mismatch_ip6, 8081)
send_udp(socket.AF_INET, "127.0.0.1", 53536, b"udp4-owner-match")
send_udp(socket.AF_INET, "127.0.0.2", 53536, b"udp4-owner-mismatch")
send_udp(socket.AF_INET6, "::1", 53536, b"udp6-owner-match")
send_udp(socket.AF_INET6, mismatch_ip6, 53536, b"udp6-owner-mismatch")
PY

for marker in udp4-owner-match udp6-owner-match; do
	found=false
	i=0
	while [ "$i" -lt 100 ]; do
		if grep -Fq "$marker" "$LOG"; then
			found=true
			break
		fi
		i=$((i + 1))
		sleep 0.05
	done
	if [ "$found" != true ]; then
		echo "guest did not receive expected marker: $marker" >&2
		exit 1
	fi
done

sleep 0.2
for marker in udp4-owner-mismatch udp6-owner-mismatch; do
	if grep -Fq "$marker" "$LOG"; then
		echo "guest received selector-mismatched marker: $marker" >&2
		exit 1
	fi
done

echo "PASS: HOST_TO_GUEST selectors enforced for IPv4/IPv6 TCP/UDP"
