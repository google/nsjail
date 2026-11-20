#!/bin/sh
# Regression test: with --execute_fd, nsjail starts the binary with
# execveat(fd, "", ..., AT_EMPTY_PATH). The --seccomp_unotify report must name
# that binary, not an empty path.
# Run directly or through: make test-unotify-execute-fd
set -eu

nsjail_bin=${1:-./nsjail}
report=$(mktemp "${TMPDIR:-/tmp}/nsjail-unotify-report.XXXXXXXX")
trap 'rm -f "$report"' EXIT HUP INT TERM

target=$(readlink -f /bin/true)

if ! "$nsjail_bin" -q -Mo --execute_fd --seccomp_unotify \
    --seccomp_unotify_report "$report" \
    --disable_clone_newuser --disable_clone_newnet --disable_clone_newcgroup \
    --disable_clone_newns --disable_clone_newpid --disable_clone_newipc \
    --disable_clone_newuts --disable_proc -- /bin/true; then
    echo "SKIP: seccomp user notifications are not available here"
    exit 77
fi

# Print the path of each fs_access record that lists an execveat call.
paths=$(awk '
    /^fs_access \{/ { path = ""; exec = 0 }
    /^  path: / { path = $0; sub(/^  path: /, "", path) }
    /name: "execveat"/ { exec = 1 }
    /^\}/ { if (exec) print path }
' "$report")

if [ "$paths" != "\"$target\"" ]; then
    echo "FAIL: execveat record has path $paths, expected \"$target\""
    exit 1
fi
echo "PASS: execveat record has path $paths"
