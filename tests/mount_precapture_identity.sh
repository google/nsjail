#!/bin/bash
set -euo pipefail

if [ "$#" -ne 7 ]; then
	echo "usage: $0 <nsjail-bin> <old|new> <bind_file|bind_dir|tmpfs> <vulnerable|fixed> <default|disable_clone_newuser> <leaf|prefix> <restore|persistent>" >&2
	exit 2
fi

NSJAIL_BIN="$1"
BACKEND="$2"
CASE_NAME="$3"
STATE="$4"
CLONE_PROFILE="$5"
EXCHANGE_POINT="$6"
SWAP_MODE="$7"

case "$BACKEND" in
old|new) ;;
*)
	echo "unsupported backend: $BACKEND" >&2
	exit 2
	;;
esac

case "$CASE_NAME" in
bind_file|bind_dir|tmpfs) ;;
*)
	echo "unsupported case: $CASE_NAME" >&2
	exit 2
	;;
esac

case "$STATE" in
vulnerable|fixed) ;;
*)
	echo "unsupported state: $STATE" >&2
	exit 2
	;;
esac

case "$CLONE_PROFILE" in
default|disable_clone_newuser) ;;
*)
	echo "unsupported clone profile: $CLONE_PROFILE" >&2
	exit 2
	;;
esac

case "$EXCHANGE_POINT" in
leaf|prefix) ;;
*)
	echo "unsupported exchange point: $EXCHANGE_POINT" >&2
	exit 2
	;;
esac

case "$SWAP_MODE" in
restore|persistent) ;;
*)
	echo "unsupported swap mode: $SWAP_MODE" >&2
	exit 2
	;;
esac

export NSJAIL_BIN BACKEND CASE_NAME STATE CLONE_PROFILE EXCHANGE_POINT SWAP_MODE

unshare --map-auto --map-root-user --user --mount --net --fork \
	bash --noprofile --norc <<'EOF'
set -euo pipefail

copy_runtime() {
	local src_bin="$1"
	local dest_bin="$2"

	install -D "$src_bin" "$ROOTFS$dest_bin"
	ldd "$src_bin" | awk '($3 ~ /^\//) { print $3 } ($1 ~ /^\//) { print $1 }' |
		while read -r lib; do
			[ -n "$lib" ] || continue
			install -D "$lib" "$ROOTFS$lib"
		done
}

describe_path() {
	local path="$1"
	if [ ! -e "$path" ] && [ ! -L "$path" ]; then
		echo "missing"
		return
	fi
	local desc
	desc="$(stat -c 'type=%F uid=%u gid=%g mode=%a inode=%i dev=%d' "$path" 2>/dev/null || true)"
	if [ -L "$path" ]; then
		desc="$desc link=$(readlink "$path")"
	fi
	echo "$desc"
}

describe_ns_path() {
	local path="$1"
	describe_path "/proc/$inspect_pid/root$path"
}

mountinfo_for_suffix() {
	local suffix="$1"
	local info
	info="$(awk -v want="$suffix" 'substr($5, length($5) - length(want) + 1) == want {print $0}' "/proc/$inspect_pid/mountinfo" 2>/dev/null || true)"
	if [ -z "$info" ]; then
		echo "missing"
		return
	fi
	echo "$info"
}

mountpoint_path_for_suffix() {
	local suffix="$1"
	awk -v want="$suffix" 'substr($5, length($5) - length(want) + 1) == want {print $5; exit}' "/proc/$inspect_pid/mountinfo" 2>/dev/null || true
}

resolve_inspect_pid() {
	local child=""
	child="$(pgrep -P "$ns_pid" | head -n1 || true)"
	if [ -n "$child" ]; then
		inspect_pid="$child"
	else
		inspect_pid="$ns_pid"
	fi
}

attacker_shell=(bash --noprofile --norc)
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	attacker_shell=(setpriv --reuid 1 --regid 1 --clear-groups bash --noprofile --norc)
fi

run_as_attacker() {
	"${attacker_shell[@]}" -c "$1"
}

wait_for_event() {
	local want="$1"
	local got=""
	while true; do
		if ! IFS= read -r -t 15 got <&3; then
			echo "hook_timeout=$want"
			return 1
		fi
		echo "hook_event=$got"
		if [ "$got" = "$want" ]; then
			return 0
		fi
		printf 'continue\n' >&4
	done
}

send_continue() {
	printf 'continue\n' >&4
}

wait_for_release_event() {
	local want="$1"
	local got=""
	while true; do
		if ! IFS= read -r -t 15 got <&3; then
			echo "hook_timeout=$want"
			return 1
		fi
		echo "hook_event=$got"
		if [ "$got" = "$want" ]; then
			return 0
		fi
		send_continue
	done
}

swap_in() {
	env SWAP_PATH="$swap_path" SWAP_SAVE="$swap_save" EXCHANGE_POINT="$EXCHANGE_POINT" LEAF_NAME="$leaf_name" REPLACEMENT_KIND="$replacement_kind" "${attacker_shell[@]}" -c '
		set -euo pipefail
		echo "swap_path_before=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i dev=%d'\'' "$SWAP_PATH")"
		mv "$SWAP_PATH" "$SWAP_SAVE"
		case "$EXCHANGE_POINT" in
		leaf)
			case "$REPLACEMENT_KIND" in
			file)
				: >"$SWAP_PATH"
				chmod 0666 "$SWAP_PATH"
				;;
			dir)
				mkdir "$SWAP_PATH"
				chmod 0777 "$SWAP_PATH"
				;;
			esac
			;;
		prefix)
			mkdir "$SWAP_PATH"
			chmod 0777 "$SWAP_PATH"
			case "$REPLACEMENT_KIND" in
			file)
				: >"$SWAP_PATH/$LEAF_NAME"
				chmod 0666 "$SWAP_PATH/$LEAF_NAME"
				;;
			dir)
				mkdir "$SWAP_PATH/$LEAF_NAME"
				chmod 0777 "$SWAP_PATH/$LEAF_NAME"
				;;
			esac
			;;
		esac
		echo "swap_path_after=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i dev=%d'\'' "$SWAP_PATH")"
		echo "swap_save_after=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i dev=%d'\'' "$SWAP_SAVE")"
	'
}

restore_swap() {
	env SWAP_PATH="$swap_path" SWAP_SAVE="$swap_save" EXCHANGE_POINT="$EXCHANGE_POINT" LEAF_NAME="$leaf_name" "${attacker_shell[@]}" -c '
		set -euo pipefail
		case "$EXCHANGE_POINT" in
		leaf)
			if [ -d "$SWAP_PATH" ] && [ ! -L "$SWAP_PATH" ]; then
				rmdir "$SWAP_PATH"
			else
				rm -f "$SWAP_PATH"
			fi
			;;
		prefix)
			rm -rf "$SWAP_PATH"
			;;
		esac
		mv "$SWAP_SAVE" "$SWAP_PATH"
		echo "swap_restore=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i dev=%d'\'' "$SWAP_PATH")"
	'
}

collect_ns_snapshot() {
	local label="$1"
	local current_desc current_mountinfo current_mp saved_desc saved_mountinfo saved_mp
	current_desc="$(describe_ns_path "$mount_dst")"
	current_mountinfo="$(mountinfo_for_suffix "$mount_dst")"
	printf -v "${label}_ns_current" '%s' "$current_desc"
	printf -v "${label}_ns_current_mountinfo" '%s' "$current_mountinfo"
	echo "${label}_ns_current=$current_desc"
	echo "${label}_ns_current_mountinfo=$current_mountinfo"
	local current_mp=""
	current_mp="$(mountpoint_path_for_suffix "$mount_dst")"
	if [ -n "$current_mp" ]; then
		local current_mp_desc
		current_mp_desc="$(describe_path "$current_mp")"
		printf -v "${label}_ns_current_mountpoint" '%s' "$current_mp"
		printf -v "${label}_ns_current_mountpoint_desc" '%s' "$current_mp_desc"
		echo "${label}_ns_current_mountpoint=$current_mp"
		echo "${label}_ns_current_mountpoint_desc=$current_mp_desc"
	fi
	saved_desc="$(describe_ns_path "$saved_ns_path")"
	saved_mountinfo="$(mountinfo_for_suffix "$saved_ns_path")"
	printf -v "${label}_ns_saved" '%s' "$saved_desc"
	printf -v "${label}_ns_saved_mountinfo" '%s' "$saved_mountinfo"
	echo "${label}_ns_saved=$saved_desc"
	echo "${label}_ns_saved_mountinfo=$saved_mountinfo"
	local saved_mp=""
	saved_mp="$(mountpoint_path_for_suffix "$saved_ns_path")"
	if [ -n "$saved_mp" ]; then
		local saved_mp_desc
		saved_mp_desc="$(describe_path "$saved_mp")"
		printf -v "${label}_ns_saved_mountpoint" '%s' "$saved_mp"
		printf -v "${label}_ns_saved_mountpoint_desc" '%s' "$saved_mp_desc"
		echo "${label}_ns_saved_mountpoint=$saved_mp"
		echo "${label}_ns_saved_mountpoint_desc=$saved_mp_desc"
	fi
}

collect_result() {
	set +e
	wait "$ns_pid"
	rc=$?
	set -e

	echo "exit_code=$rc"
	if [ -f "$STDOUT_LOG" ] && grep -q '^CHILD_EXECUTED=yes$' "$STDOUT_LOG"; then
		child_executed=yes
	else
		child_executed=no
	fi
	echo "child_executed=$child_executed"
	echo "outside_after=$(describe_path "$outside_path")"
	echo "current_after=$(describe_path "$current_outside_path")"
	echo "saved_after=$(describe_path "$saved_outside_path")"
	printf '%s\n' '--- stdout ---'
	cat "$STDOUT_LOG" 2>/dev/null || true
	printf '%s\n' '--- stderr ---'
	cat "$STDERR_LOG" 2>/dev/null || true
}

LAB="$(mktemp -d /tmp/nsjail-precapture.XXXXXX)"
mount -t tmpfs none "$LAB"
ROOTFS="$LAB/rootfs"
SRC="$LAB/src"
SAFE="$LAB/safe"
PROTECTED="$LAB/protected"
HOOKDIR="$LAB/hooks"
STDOUT_LOG="$LAB/run.out"
STDERR_LOG="$LAB/run.err"
mkdir -p "$ROOTFS/tmp" "$ROOTFS/bin" "$ROOTFS/usr/bin" "$SRC/racedir" "$SAFE/dirsrc" "$PROTECTED" "$HOOKDIR"
mkfifo "$HOOKDIR/events.fifo" "$HOOKDIR/control.fifo"
exec 3<>"$HOOKDIR/events.fifo"
exec 4<>"$HOOKDIR/control.fifo"

copy_runtime /bin/sh /bin/sh
copy_runtime /usr/bin/awk /usr/bin/awk
copy_runtime /usr/bin/stat /usr/bin/stat
copy_runtime /usr/bin/touch /usr/bin/touch

printf '%s\n' 'seed' >"$SAFE/filesrc"
printf '%s\n' '#!/bin/sh' 'echo EXEC_OK' >"$SAFE/dirsrc/run.sh"
chmod 0755 "$SAFE/dirsrc/run.sh"

if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	chown -R 1:1 "$SRC"
fi
chmod 0755 "$SRC" "$SRC/racedir"
chmod 0700 "$PROTECTED"

nsjail_base=(env NSJAIL_TEST_HOOK_DIR="$HOOKDIR" "$NSJAIL_BIN" -q -Mo)
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	nsjail_base+=(--disable_clone_newuser)
fi
nsjail_base+=(--experimental_mnt "$BACKEND" --chroot "$ROOTFS")

case "$BACKEND" in
old) trigger_prefix="legacy.before_post_attach_capture:" ;;
new) trigger_prefix="new.before_post_attach_capture:" ;;
esac
release_event="mnt.before_visibility_check"

case "$CASE_NAME" in
bind_file)
	leaf_name="file_target"
	replacement_kind="file"
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/filesrc:/mnt/racedir/$leaf_name" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/file_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/file_target;
		printf x >> /mnt/racedir/file_target && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	expected_inside_type_substring="regular"
	;;
bind_dir)
	leaf_name="dir_target"
	replacement_kind="dir"
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/dirsrc:/mnt/racedir/$leaf_name" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/dir_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/dir_target;
		/usr/bin/touch /mnt/racedir/dir_target/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	expected_inside_type_substring="directory"
	;;
tmpfs)
	leaf_name="tmp_target"
	replacement_kind="dir"
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -m none:/mnt/racedir/$leaf_name:tmpfs:ro -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/tmp_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/tmp_target;
		/usr/bin/touch /mnt/racedir/tmp_target/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	expected_inside_type_substring="directory"
	;;
esac

mount_dst="/mnt/racedir/$leaf_name"
outside_path="$PROTECTED/unexpected"

case "$EXCHANGE_POINT" in
leaf)
	swap_path="$SRC/racedir/$leaf_name"
	swap_save="$SRC/racedir/${leaf_name}.orig"
	current_outside_path="$swap_path"
	saved_outside_path="$swap_save"
	saved_ns_path="/mnt/racedir/${leaf_name}.orig"
	;;
prefix)
	swap_path="$SRC/racedir"
	swap_save="$SRC/racedir.orig"
	current_outside_path="$swap_path/$leaf_name"
	saved_outside_path="$swap_save/$leaf_name"
	saved_ns_path="/mnt/racedir.orig/$leaf_name"
	;;
esac

trigger_event="${trigger_prefix}${mount_dst}"

echo "case=$CASE_NAME"
echo "backend=$BACKEND"
echo "state=$STATE"
echo "clone_profile=$CLONE_PROFILE"
echo "exchange_point=$EXCHANGE_POINT"
echo "swap_mode=$SWAP_MODE"
echo "trigger_event=$trigger_event"
echo "release_event=$release_event"
echo "command=$(printf '%q ' "${cmd[@]}")"
echo "launcher=$(id)"
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	echo "attacker_id=$(setpriv --reuid 1 --regid 1 --clear-groups id)"
else
	echo "attacker_id=same-uid-default-profile"
fi
echo "attacker_can_write_protected=$(run_as_attacker 'if touch \"$PROTECTED/attacker_nope\" 2>/dev/null; then echo yes; else echo no; fi')"
echo "mount_dst=$mount_dst"
echo "saved_ns_path=$saved_ns_path"
echo "outside_before=$(describe_path "$outside_path")"
echo "current_before=$(describe_path "$current_outside_path")"
echo "saved_before=$(describe_path "$saved_outside_path")"

set +e
"${cmd[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
ns_pid=$!
set -e
echo "ns_pid=$ns_pid"
resolve_inspect_pid
echo "inspect_pid=$inspect_pid"

if ! wait_for_event "$trigger_event"; then
	resolve_inspect_pid
	collect_result
	exit 1
fi
resolve_inspect_pid
collect_ns_snapshot pre_swap
swap_in
resolve_inspect_pid
collect_ns_snapshot post_swap
send_continue

if ! wait_for_release_event "$release_event"; then
	resolve_inspect_pid
	collect_result
	exit 1
fi
resolve_inspect_pid
collect_ns_snapshot at_release

if [ "$SWAP_MODE" = "restore" ]; then
	restore_swap
	resolve_inspect_pid
	collect_ns_snapshot post_restore
else
	echo "swap_restore=skipped"
fi
send_continue

collect_result

oracle_fail=0

expect_eq() {
	local field="$1"
	local actual="$2"
	local want="$3"
	if [ "$actual" != "$want" ]; then
		echo "oracle_error=$field expected=$want actual=$actual"
		oracle_fail=1
	fi
}

expect_contains() {
	local field="$1"
	local haystack="$2"
	local needle="$3"
	if [[ "$haystack" != *"$needle"* ]]; then
		echo "oracle_error=$field expected_substring=$needle actual=$haystack"
		oracle_fail=1
	fi
}

extract_inode() {
	local text="$1"
	sed -n 's/.*inode=\([0-9][0-9]*\).*/\1/p' <<<"$text" | head -n1
}

current_desc="$(describe_path "$current_outside_path")"
saved_desc="$(describe_path "$saved_outside_path")"
inside_line="$(grep '^INSIDE_TYPE=' "$STDOUT_LOG" 2>/dev/null || true)"
inside_inode="$(extract_inode "$inside_line")"
current_inode="$(extract_inode "$current_desc")"
saved_inode="$(extract_inode "$saved_desc")"

stdout_contents="$(cat "$STDOUT_LOG" 2>/dev/null || true)"
stderr_contents="$(cat "$STDERR_LOG" 2>/dev/null || true)"

expect_eq outside_after "$(describe_path "$outside_path")" "missing"

case "$STATE:$SWAP_MODE" in
vulnerable:persistent)
	expect_eq exit_code "$rc" "0"
	expect_eq child_executed "$child_executed" "yes"
	expect_contains current_after "$current_desc" "inode="
	expect_contains saved_after "$saved_desc" "inode="
	expect_contains stdout "$stdout_contents" "INSIDE_TYPE=$expected_inside_type_substring"
	expect_contains stdout "$stdout_contents" "WRITE_OK"
	expect_eq inside_inode "$inside_inode" "$current_inode"
	if [ -n "$saved_inode" ] && [ "$inside_inode" = "$saved_inode" ]; then
		echo "oracle_error=inside_inode unexpectedly_matched_saved_inode value=$inside_inode"
		oracle_fail=1
	fi
	expect_eq at_release_ns_current_mountinfo "$at_release_ns_current_mountinfo" "missing"
	expect_contains at_release_ns_saved_mountinfo "$at_release_ns_saved_mountinfo" "$saved_ns_path"
	if [[ "$stdout_contents" == *"MOUNT_ID="* ]]; then
		echo "oracle_error=stdout expected_missing=MOUNT_ID actual=$stdout_contents"
		oracle_fail=1
	fi
	;;
vulnerable:restore)
	expect_eq exit_code "$rc" "255"
	expect_eq child_executed "$child_executed" "no"
	expect_contains stderr "$stderr_contents" "no longer refers to the attached mount"
	;;
fixed:persistent)
	expect_eq exit_code "$rc" "255"
	expect_eq child_executed "$child_executed" "no"
	expect_contains stderr "$stderr_contents" "no longer refers to the attached mount"
	;;
fixed:restore)
	expect_eq exit_code "$rc" "0"
	expect_eq child_executed "$child_executed" "yes"
	expect_contains stdout "$stdout_contents" "INSIDE_TYPE=$expected_inside_type_substring"
	expect_contains stdout "$stdout_contents" "WRITE_BLOCKED"
	expect_contains stdout "$stdout_contents" "MOUNT_ID="
	expect_contains stdout "$stdout_contents" "MOUNT_OPTS=ro"
	expect_contains post_restore_ns_current_mountinfo "$post_restore_ns_current_mountinfo" "$mount_dst"
	expect_eq post_restore_ns_saved_mountinfo "$post_restore_ns_saved_mountinfo" "missing"
	;;
esac

if [ "$oracle_fail" -eq 0 ]; then
	echo "oracle_result=pass"
else
	echo "oracle_result=fail"
	exit 1
fi
EOF
