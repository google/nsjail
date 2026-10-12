#!/bin/sh
# Integration regression test for nsjail's high-FD close-on-exec fallback.
set -eu

cd "$(dirname "$0")/.."
nsjail="$(pwd)/nsjail"
if [ ! -x "$nsjail" ]; then
    echo "FAIL: build nsjail before running this test" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/jail"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -static \
    -o "$tmp/probe" tests/high_fd_cleanup_helper.c
cp "$tmp/probe" "$tmp/jail/probe"
printf 'nsjail-high-fd-regression\n' > "$tmp/host-secret"

# No /proc is present in the chroot; unlike the original fallback, the fixed
# code retains the /proc/self/fd directory opened before entering the chroot.
# The launcher forces close_range to return ENOSYS using an inherited seccomp
# filter, even on kernels where CLOSE_RANGE_CLOEXEC is supported.
# Avoid depending on namespace creation privileges in CI. With no mount
# namespace, nsjail uses chroot(2), which requires root (run with sudo).
base_args="--mode o --quiet --disable_proc --disable_clone_newuser --disable_clone_newnet --disable_clone_newcgroup --disable_clone_newns --disable_clone_newpid --disable_clone_newipc --disable_clone_newuts"

echo "[high-fd] inherited fd 2048 must not escape into proc-less jail"
"$tmp/probe" launch "$tmp/host-secret" "$nsjail" $base_args \
    --chroot "$tmp/jail" -- /probe probe closed

echo "[high-fd] explicit --pass_fd 2048 must remain supported"
"$tmp/probe" launch "$tmp/host-secret" "$nsjail" $base_args \
    --chroot "$tmp/jail" --pass_fd 2048 -- /probe probe open

echo "[high-fd] PASS"
