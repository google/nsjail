#!/bin/bash
# Behavioural test for the optional Landlock layer (--landlock).
#
# Without CLONE_NEWNS the mount list is not enforced by the kernel, so the jail
# is just the host filesystem. The Landlock layer derives path-beneath rules
# from the same mount list, which gives these paths real enforcement.
#
# Exit codes: 0 = pass, 1 = fail, 77 = skipped (kernel without Landlock).
set -u

NSJAIL="${NSJAIL:-./nsjail}"
fail=0

if ! grep -qw landlock /sys/kernel/security/lsm 2>/dev/null; then
	echo "SKIP: Landlock is not enabled in this kernel"
	exit 77
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/ro" "$work/rw" "$work/noexec"
echo secret >"$work/ro/file"
cp /bin/true "$work/noexec/run"
chmod +x "$work/noexec/run"

base=("$NSJAIL" -Mo --disable_clone_newns --quiet
	-R /bin -R /lib -R /lib64 -R /usr -R "$work/ro" -B "$work/rw"
	-m "$work/noexec:$work/noexec:none:bind,noexec")

check() { # name, expected (0|1), actual rc
	if [ "$2" = "$3" ]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (expected rc=$2, got rc=$3)"
		fail=1
	fi
}

# 1. Control: without --landlock the host is fully readable.
"${base[@]}" -- /bin/cat /etc/hostname >/dev/null 2>&1
check "control: /etc/hostname readable without landlock" 0 $?

# 2. A path outside the mount list is denied.
"${base[@]}" --landlock best_effort -- /bin/cat /etc/hostname >/dev/null 2>&1
check "landlock: /etc/hostname denied (not in mount list)" 1 $?

# 3. Binaries/libraries from the mount list still execute.
"${base[@]}" --landlock best_effort -- /bin/true >/dev/null 2>&1
check "landlock: /bin/true still runs" 0 $?

# 4. Read-only mount: readable, not writable.
"${base[@]}" --landlock best_effort -- /bin/cat "$work/ro/file" >/dev/null 2>&1
check "landlock: ro path readable" 0 $?
"${base[@]}" --landlock best_effort -- /bin/touch "$work/ro/new" >/dev/null 2>&1
check "landlock: ro path not writable" 1 $?

# 5. Read-write mount: writable.
"${base[@]}" --landlock best_effort -- /bin/touch "$work/rw/new" >/dev/null 2>&1
check "landlock: rw path writable" 0 $?

# 6. Control: ro path IS writable without landlock (no mount ns).
"${base[@]}" -- /bin/touch "$work/ro/new2" >/dev/null 2>&1
check "control: ro path writable without landlock" 0 $?

# 7. noexec mount: readable, not executable under Landlock.
"${base[@]}" --landlock required -- /bin/head -c 4 "$work/noexec/run" >/dev/null 2>&1
check "landlock: noexec path readable" 0 $?
"${base[@]}" --landlock required -- "$work/noexec/run" >/dev/null 2>&1
check "landlock: noexec path not executable" 255 $?

# 8. Config file (textproto): landlock: LANDLOCK_REQUIRED.
cat >"$work/ll.cfg" <<EOF
mode: ONCE
clone_newns: false
landlock: LANDLOCK_REQUIRED
mount { src: "/bin" dst: "/bin" is_bind: true }
mount { src: "/lib" dst: "/lib" is_bind: true }
mount { src: "/lib64" dst: "/lib64" is_bind: true }
mount { src: "/usr" dst: "/usr" is_bind: true }
EOF
"$NSJAIL" --config "$work/ll.cfg" --quiet -- /bin/true >/dev/null 2>&1
check "landlock: config LANDLOCK_REQUIRED allows mounted path" 0 $?
"$NSJAIL" --config "$work/ll.cfg" --quiet -- /bin/cat /etc/hostname >/dev/null 2>&1
check "landlock: config LANDLOCK_REQUIRED denies unmounted path" 1 $?

exit $fail
