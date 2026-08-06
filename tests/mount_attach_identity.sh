#!/bin/bash
set -euo pipefail

if [ "$#" -lt 5 ]; then
	echo "usage: $0 <nsjail-bin> <old|new> <bind_file|bind_dir|tmpfs> <patched|v5reopen> <default|disable_clone_newuser> [restore|persistent]" >&2
	exit 2
fi

NSJAIL_BIN="$1"
BACKEND="$2"
CASE_NAME="$3"
VARIANT="$4"
CLONE_PROFILE="$5"
SWAP_MODE="${6:-restore}"

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

case "$VARIANT" in
patched|v5reopen) ;;
*)
	echo "unsupported variant: $VARIANT" >&2
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

case "$SWAP_MODE" in
restore|persistent) ;;
*)
	echo "unsupported swap mode: $SWAP_MODE" >&2
	exit 2
	;;
esac

if [ "$VARIANT" = "v5reopen" ] && [ "$SWAP_MODE" = "persistent" ]; then
	echo "v5reopen only supports restore mode" >&2
	exit 2
fi

export NSJAIL_BIN BACKEND CASE_NAME VARIANT CLONE_PROFILE SWAP_MODE

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
	desc="$(stat -c 'type=%F uid=%u gid=%g mode=%a inode=%i' "$path" 2>/dev/null || true)"
	if [ -L "$path" ]; then
		desc="$desc link=$(readlink "$path")"
	fi
	echo "$desc"
}

attacker_shell=(bash --noprofile --norc)
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	attacker_shell=(setpriv --reuid 1 --regid 1 --clear-groups bash --noprofile --norc)
fi

swap_in() {
	env SWAP_PATH="$swap_path" SWAP_SAVE="$swap_save" SWAP_KIND="$swap_kind" "${attacker_shell[@]}" -c '
		set -euo pipefail
		echo "swap_before=$(stat -c '\''inode=%i mode=%a uid=%u gid=%g'\'' "$SWAP_PATH")"
		mv "$SWAP_PATH" "$SWAP_SAVE"
		case "$SWAP_KIND" in
		file)
			: >"$SWAP_PATH"
			chmod 0644 "$SWAP_PATH"
			;;
		dir)
			mkdir "$SWAP_PATH"
			chmod 0755 "$SWAP_PATH"
			;;
		*)
			echo "unsupported swap kind: $SWAP_KIND" >&2
			exit 1
			;;
		esac
		echo "swap_after=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i'\'' "$SWAP_PATH")"
		echo "swap_saved=$(stat -c '\''type=%F uid=%u gid=%g mode=%a inode=%i'\'' "$SWAP_SAVE")"
	'
}

restore_swap() {
	env SWAP_PATH="$swap_path" SWAP_SAVE="$swap_save" "${attacker_shell[@]}" -c '
		set -euo pipefail
		if [ -d "$SWAP_PATH" ] && [ ! -L "$SWAP_PATH" ]; then
			rmdir "$SWAP_PATH"
		else
			rm -f "$SWAP_PATH"
		fi
		mv "$SWAP_SAVE" "$SWAP_PATH"
		echo "swap_restore=$(stat -c '\''inode=%i mode=%a uid=%u gid=%g'\'' "$SWAP_PATH")"
	'
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

drain_hook_events_until_exit() {
	local got=""
	while kill -0 "$ns_pid" 2>/dev/null; do
		if IFS= read -r -t 1 got <&3; then
			echo "hook_event=$got"
			send_continue
		fi
	done
}

collect_process_result() {
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
	echo "inside_after=$(describe_path "$inside_path")"
	printf '%s\n' '--- stdout ---'
	cat "$STDOUT_LOG" 2>/dev/null || true
	printf '%s\n' '--- stderr ---'
	cat "$STDERR_LOG" 2>/dev/null || true
}

abort_and_collect_process_result() {
	if kill -0 "$ns_pid" 2>/dev/null; then
		kill "$ns_pid" 2>/dev/null || true
	fi
	collect_process_result
}

LAB="$(mktemp -d /tmp/nsjail-identity.XXXXXX)"
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
copy_runtime /usr/bin/cat /usr/bin/cat
copy_runtime /usr/bin/grep /usr/bin/grep
copy_runtime /usr/bin/readlink /usr/bin/readlink
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

case "$VARIANT:$BACKEND" in
patched:old) trigger_prefix="legacy.after_attach:" ;;
patched:new) trigger_prefix="new.after_attach:" ;;
v5reopen:old) trigger_prefix="legacy.before_post_attach_capture:" ;;
v5reopen:new) trigger_prefix="new.before_post_attach_capture:" ;;
esac
release_event="mnt.before_visibility_check"

case "$CASE_NAME" in
bind_file)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/filesrc:/mnt/racedir/file_target" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/file_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/file_target;
		printf x >> /mnt/racedir/file_target && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path="$PROTECTED/unexpected"
	inside_path="$SRC/racedir/file_target"
	expected_type="regular file"
	expected_desc_type="regular"
	mount_dst="/mnt/racedir/file_target"
	swap_path="$SRC/racedir/file_target"
	swap_save="$SRC/racedir/file_target.orig"
	swap_kind="file"
	;;
bind_dir)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/dirsrc:/mnt/racedir/dir_target" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/dir_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/dir_target;
		/usr/bin/touch /mnt/racedir/dir_target/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path="$PROTECTED/unexpected"
	inside_path="$SRC/racedir/dir_target"
	expected_type="directory"
	expected_desc_type="directory"
	mount_dst="/mnt/racedir/dir_target"
	swap_path="$SRC/racedir/dir_target"
	swap_save="$SRC/racedir/dir_target.orig"
	swap_kind="dir"
	;;
tmpfs)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -m none:/mnt/racedir/tmp_target:tmpfs:ro -- /bin/sh -c
		'echo CHILD_EXECUTED=yes;
		/usr/bin/awk '"'"'$5=="/mnt/racedir/tmp_target"{print "MOUNT_ID="$1; print "MOUNT_OPTS="$6}'"'"' /proc/self/mountinfo;
		/usr/bin/stat -c "INSIDE_TYPE=%F inode=%i" /mnt/racedir/tmp_target;
		/usr/bin/touch /mnt/racedir/tmp_target/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path="$PROTECTED/unexpected"
	inside_path="$SRC/racedir/tmp_target"
	expected_type="directory"
	expected_desc_type="directory"
	mount_dst="/mnt/racedir/tmp_target"
	swap_path="$SRC/racedir/tmp_target"
	swap_save="$SRC/racedir/tmp_target.orig"
	swap_kind="dir"
	;;
esac

trigger_event="${trigger_prefix}${mount_dst}"

echo "case=$CASE_NAME"
echo "backend=$BACKEND"
echo "variant=$VARIANT"
echo "clone_profile=$CLONE_PROFILE"
echo "swap_mode=$SWAP_MODE"
echo "trigger_event=$trigger_event"
echo "release_event=$release_event"
echo "command=$(printf '%q ' "${cmd[@]}")"
echo "racedir_before=$(describe_path "$SRC/racedir")"
echo "leaf_before=$(describe_path "$swap_path")"
echo "protected_before=$(describe_path "$PROTECTED")"
echo "outside_before=$(describe_path "$outside_path")"
echo "inside_before=$(describe_path "$inside_path")"

set +e
"${cmd[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
ns_pid=$!
set -e

if ! wait_for_event "$trigger_event"; then
	abort_and_collect_process_result
	exit 1
fi
swap_in
send_continue

if [ "$VARIANT" = "v5reopen" ]; then
	drain_hook_events_until_exit
	collect_process_result
	echo "swap_restore=deferred_to_namespace_cleanup"
else
	if ! wait_for_event "$release_event"; then
		abort_and_collect_process_result
		exit 1
	fi
	if [ "$SWAP_MODE" = "restore" ]; then
		restore_swap
	else
		echo "swap_restore=skipped"
	fi
	send_continue
	collect_process_result
fi

if [ "$SWAP_MODE" = "persistent" ] && [ -e "$swap_save" ]; then
	echo "swap_cleanup_pending=yes"
	restore_swap >/dev/null
fi

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

expect_stdout_contains() {
	local want="$1"
	if ! grep -Fq -- "$want" "$STDOUT_LOG"; then
		echo "oracle_error=stdout expected_substring=$want"
		oracle_fail=1
	fi
}

expect_desc_contains() {
	local field="$1"
	local actual="$2"
	local want="$3"
	if [[ "$actual" != *"$want"* ]]; then
		echo "oracle_error=$field expected_substring=$want actual=$actual"
		oracle_fail=1
	fi
}

case "$VARIANT:$SWAP_MODE" in
patched:restore)
	expect_eq exit_code "$rc" "0"
	expect_eq child_executed "$child_executed" "yes"
	expect_eq outside_after "$(describe_path "$outside_path")" "missing"
	expect_stdout_contains "WRITE_BLOCKED"
	expect_stdout_contains "MOUNT_ID="
	expect_stdout_contains "MOUNT_OPTS=ro"
	expect_stdout_contains "INSIDE_TYPE=$expected_type"
	expect_desc_contains inside_after "$(describe_path "$inside_path")" "type=$expected_desc_type"
	expect_desc_contains inside_after "$(describe_path "$inside_path")" "inode="
	;;
patched:persistent)
	expect_eq exit_code "$rc" "255"
	expect_eq child_executed "$child_executed" "no"
	expect_eq outside_after "$(describe_path "$outside_path")" "missing"
	expect_desc_contains stderr "$(cat "$STDERR_LOG")" "no longer refers to the attached mount"
	;;
v5reopen:restore)
	expect_eq exit_code "$rc" "255"
	expect_eq child_executed "$child_executed" "no"
	expect_eq outside_after "$(describe_path "$outside_path")" "missing"
	expect_desc_contains stderr "$(cat "$STDERR_LOG")" "mount_setattr(fd="
	expect_desc_contains stderr "$(cat "$STDERR_LOG")" "Failed to apply final flags"
	;;
esac

if [ "$oracle_fail" -eq 0 ]; then
	echo "oracle_result=pass"
else
	echo "oracle_result=fail"
fi

printf '%s\n' '--- stdout ---'
cat "$STDOUT_LOG"
printf '%s\n' '--- stderr ---'
cat "$STDERR_LOG"

if [ "$oracle_fail" -ne 0 ]; then
	exit 1
fi
EOF
