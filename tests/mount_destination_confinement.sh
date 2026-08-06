#!/bin/bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
	echo "usage: $0 <nsjail-bin> <old|new> <case> [record|patched] [default|disable_clone_newuser]" >&2
	exit 2
fi

NSJAIL_BIN="$1"
BACKEND="$2"
CASE_NAME="$3"
PROFILE="${4:-record}"
CLONE_PROFILE="${5:-default}"

case "$BACKEND" in
old|new) ;;
*)
	echo "unsupported backend: $BACKEND" >&2
	exit 2
	;;
esac

case "$CASE_NAME" in
attack_mid_abs|attack_mid_rel|final_file|final_dir|safe_final_file_bind|safe_final_dir_bind|safe_final_dir_tmpfs|bind_file|bind_dir|tmpfs|dynamic_content|symlink_dst|ro_src|positive_abs|positive_rel|loop|nondir|missing|race|root_dot|parentdot|nul) ;;
*)
	echo "unsupported case: $CASE_NAME" >&2
	exit 2
	;;
esac

case "$PROFILE" in
record|patched) ;;
*)
	echo "unsupported profile: $PROFILE" >&2
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

export NSJAIL_BIN BACKEND CASE_NAME PROFILE CLONE_PROFILE

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

write_cfg() {
	local clone_newuser_cfg=true
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		clone_newuser_cfg=false
	fi
	cat >"$CFG" <<CFG
name: "mount-destination-confinement"
mode: ONCE
hostname: "NSJAIL"
cwd: "/"
mount_proc: false
clone_newuser: ${clone_newuser_cfg}
mount {
	src: "$ROOTFS"
	dst: "/"
	is_bind: true
	rw: true
}
CFG
}

append_cfg_mount() {
	cat >>"$CFG"
}

run_as_attacker() {
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		setpriv --reuid 1 --regid 1 --clear-groups bash --noprofile --norc -c "$1"
		return
	fi
	bash --noprofile --norc -c "$1"
}

attacker_shell=(bash --noprofile --norc)
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	attacker_shell=(setpriv --reuid 1 --regid 1 --clear-groups bash --noprofile --norc)
fi

LAB="$(mktemp -d /tmp/nsjail-oracle.XXXXXX)"
mount -t tmpfs none "$LAB"
ROOTFS="$LAB/rootfs"
SRC="$LAB/src"
SAFE="$LAB/safe"
PROTECTED="$LAB/protected"
CFG="$LAB/case.cfg"
STDOUT_LOG="$LAB/run.out"
STDERR_LOG="$LAB/run.err"
STRACE_LOG="$LAB/run.strace"
mkdir -p "$ROOTFS/tmp" "$ROOTFS/bin" "$ROOTFS/usr/bin" "$SRC" "$SAFE" "$PROTECTED"

nsjail_base=("$NSJAIL_BIN" -q -Mo)
if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	nsjail_base+=(--disable_clone_newuser)
fi
nsjail_base+=(--experimental_mnt "$BACKEND" --chroot "$ROOTFS")

copy_runtime /bin/sh /bin/sh
copy_runtime /bin/true /bin/true
copy_runtime /usr/bin/stat /usr/bin/stat
copy_runtime /usr/bin/readlink /usr/bin/readlink
copy_runtime /usr/bin/cat /usr/bin/cat
copy_runtime /usr/bin/mkdir /usr/bin/mkdir
copy_runtime /usr/bin/touch /usr/bin/touch

if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
	chown -R 1:1 "$SRC"
fi
chmod 0755 "$SRC"
chmod 0700 "$PROTECTED"
mkdir -p "$SAFE/share" "$SAFE/dirsrc"
echo safe >"$SAFE/share/base.txt"
echo seed >"$SAFE/filesrc"
echo safe >"$SAFE/dirsrc/base.txt"

case "$CASE_NAME" in
attack_mid_abs)
	mkdir -p "$PROTECTED/mid_abs"
	SRC="$SRC" PROTECTED="$PROTECTED" run_as_attacker 'ln -s "$PROTECTED/mid_abs" "$SRC/mid_escape"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/mid_escape/leak -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$PROTECTED/mid_abs/leak"
	inside_path=""
	expected="outside_symlink_escape"
	;;
attack_mid_rel)
	REL_PROTECTED="$(mktemp -d /tmp/nsjail-rel-protected.XXXXXX)"
	chmod 0700 "$REL_PROTECTED"
	mkdir -p "$SRC/sub" "$REL_PROTECTED/mid_rel"
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		chown 1:1 "$SRC/sub"
	fi
	rel_target="../../../$(basename "$REL_PROTECTED")/mid_rel"
	SRC="$SRC" run_as_attacker "ln -s '$rel_target' \"\$SRC/sub/rel_escape\""
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/sub/rel_escape/leak -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$REL_PROTECTED/mid_rel/leak"
	inside_path=""
	expected="outside_symlink_escape"
	;;
final_file)
	SRC="$SRC" PROTECTED="$PROTECTED" run_as_attacker 'ln -s "$PROTECTED/outfile" "$SRC/final_escape"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -B /bin/true:/mnt/final_escape -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$PROTECTED/outfile"
	inside_path=""
	expected="final_file_symlink"
	;;
final_dir)
	mkdir -p "$PROTECTED/final_dir_target"
	SRC="$SRC" PROTECTED="$PROTECTED" run_as_attacker 'ln -s "$PROTECTED/final_dir_target" "$SRC/final_dir"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -m none:/mnt/final_dir:tmpfs:rw -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "INSIDE_TYPE=%F" /mnt/final_dir; echo escaped > /mnt/final_dir/child_file; echo WRITE_OK'
	)
	outside_path="$PROTECTED/final_dir_target/child_file"
	inside_path=""
	expected="final_dir_symlink_mountpoint"
	;;
safe_final_file_bind)
	mkdir -p "$ROOTFS/legit"
	: >"$ROOTFS/legit/file_target"
	SRC="$SRC" run_as_attacker 'ln -s /legit/file_target "$SRC/final_file_inroot"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/filesrc:/mnt/final_file_inroot" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "PATH_TYPE=%F" /mnt/final_file_inroot; /usr/bin/stat -Lc "TARGET_TYPE=%F" /mnt/final_file_inroot; printf x >> /mnt/final_file_inroot && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path=""
	inside_path=""
	expected="safe_final_file_bind_ok"
	;;
safe_final_dir_bind)
	mkdir -p "$ROOTFS/legit/dir_target"
	SRC="$SRC" run_as_attacker 'ln -s /legit/dir_target "$SRC/final_dir_inroot"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -R "$SAFE/dirsrc:/mnt/final_dir_inroot" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "PATH_TYPE=%F" /mnt/final_dir_inroot; /usr/bin/stat -Lc "TARGET_TYPE=%F" /mnt/final_dir_inroot; /usr/bin/touch /mnt/final_dir_inroot/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path=""
	inside_path=""
	expected="safe_final_dir_bind_ok"
	;;
safe_final_dir_tmpfs)
	mkdir -p "$ROOTFS/legit"
	SRC="$SRC" run_as_attacker '
		mkdir -p "$SRC/rel"
		ln -s ../legit_tmp "$SRC/rel/final_tmp_inroot"
	'
	mkdir -p "$SRC/legit_tmp"
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -m none:/mnt/rel/final_tmp_inroot:tmpfs:rw -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "PATH_TYPE=%F" /mnt/rel/final_tmp_inroot; /usr/bin/stat -Lc "TARGET_TYPE=%F" /mnt/rel/final_tmp_inroot; echo tmpfs > /mnt/rel/final_tmp_inroot/child_file; echo WRITE_OK'
	)
	outside_path=""
	inside_path=""
	expected="safe_final_dir_tmpfs_ok"
	;;
bind_file)
	cmd=(
		"${nsjail_base[@]}" -B /bin/true:/mnt/file_bind -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "INSIDE_TYPE=%F" /mnt/file_bind'
	)
	outside_path=""
	inside_path=""
	expected="bind_file_ok"
	;;
bind_dir)
	cmd=(
		"${nsjail_base[@]}" -B "$SAFE:/mnt/dir_bind" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "INSIDE_TYPE=%F" /mnt/dir_bind; echo binddir > /mnt/dir_bind/child_file; echo WRITE_OK'
	)
	outside_path="$SAFE/child_file"
	inside_path=""
	expected="bind_dir_ok"
	;;
tmpfs)
	cmd=(
		"${nsjail_base[@]}" -m none:/mnt/tmpfs:tmpfs:rw -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "INSIDE_TYPE=%F" /mnt/tmpfs; echo tmpfs > /mnt/tmpfs/child_file; echo WRITE_OK'
	)
	outside_path=""
	inside_path=""
	expected="tmpfs_ok"
	;;
dynamic_content)
	write_cfg
	append_cfg_mount <<CFG
mount {
	dst: "/mnt/content.txt"
	src_content: "dynamic-content"
	is_dir: false
	rw: false
}
exec_bin {
	path: "/bin/sh"
	arg: "-c"
	arg: "echo CHILD_EXECUTED=yes; /usr/bin/stat -c \"INSIDE_TYPE=%F\" /mnt/content.txt; echo CONTENT=\$(/usr/bin/cat /mnt/content.txt)"
}
CFG
	cmd=("$NSJAIL_BIN" -q -Mo --config "$CFG")
	outside_path=""
	inside_path=""
	expected="dynamic_content_ok"
	;;
symlink_dst)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/link_ok -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$SRC/link_ok"
	inside_path=""
	expected="symlink_ok"
	;;
ro_src)
	cmd=(
		"${nsjail_base[@]}" -R "$SRC:/mnt" -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/touch /mnt/blocked && echo WRITE_OK || echo WRITE_BLOCKED'
	)
	outside_path="$SRC/blocked"
	inside_path=""
	expected="ro_bind_blocks_write"
	;;
positive_abs)
	SRC="$SRC" run_as_attacker 'ln -s /safe "$SRC/inroot_abs"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" -B "$SAFE:/safe" --symlink /bin/true:/mnt/inroot_abs/ok -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$SAFE/ok"
	inside_path=""
	expected="absolute_in_root_symlink_ok"
	;;
positive_rel)
	mkdir -p "$SRC/dir/rel_target"
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		chown 1:1 "$SRC/dir" "$SRC/dir/rel_target"
	fi
	SRC="$SRC" run_as_attacker 'ln -s rel_target "$SRC/dir/rel_link"'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/dir/rel_link/ok -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$SRC/dir/rel_target/ok"
	inside_path=""
	expected="relative_in_root_symlink_ok"
	;;
loop)
	SRC="$SRC" run_as_attacker '
		ln -s loop2 "$SRC/loop1"
		ln -s loop1 "$SRC/loop2"
	'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/loop1/leak -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path=""
	inside_path=""
	expected="symlink_loop_rejected"
	;;
nondir)
	SRC="$SRC" run_as_attacker '
		: > "$SRC/notdir"
	'
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/notdir/leak -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path=""
	inside_path=""
	expected="nondir_rejected"
	;;
missing)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/new/a/b/leak -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path="$SRC/new/a/b/leak"
	inside_path=""
	expected="missing_components_created"
	;;
race)
	cmd=(
			strace -f -o "$STRACE_LOG" -e inject=symlinkat:delay_enter=500ms "${nsjail_base[@]}" -B "$SRC:/mnt"
		--symlink /bin/true:/mnt/racedir/leak -- /bin/sh -c 'echo CHILD_EXECUTED=yes'
	)
	mkdir -p "$SRC/racedir"
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		chown 1:1 "$SRC/racedir"
	fi
	chmod 0755 "$SRC/racedir"
	SRC="$SRC" PROTECTED="$PROTECTED" "${attacker_shell[@]}" <<'RACE' &
set -euo pipefail
sleep 0.1
mv "$SRC/racedir" "$SRC/racedir.dir"
ln -s "$PROTECTED" "$SRC/racedir"
sleep 1
rm -f "$SRC/racedir"
mv "$SRC/racedir.dir" "$SRC/racedir"
RACE
	swapper_pid=$!
	outside_path="$PROTECTED/leak"
	inside_path="$SRC/racedir/leak"
	expected="descriptor_confined_race"
	;;
root_dot)
	cmd=(
		"${nsjail_base[@]}" -m none:/mnt/./dot:tmpfs:rw -- /bin/sh -c
		'echo CHILD_EXECUTED=yes; /usr/bin/stat -c "INSIDE_TYPE=%F" /mnt/dot; echo dot > /mnt/dot/child_file; echo WRITE_OK'
	)
	outside_path=""
	inside_path=""
	expected="normalized_dot_ok"
	;;
parentdot)
	cmd=(
		"${nsjail_base[@]}" -B "$SRC:/mnt" --symlink /bin/true:/mnt/../escape -- /bin/sh -c
		'echo CHILD_EXECUTED=yes'
	)
	outside_path=""
	inside_path=""
	expected="parentdot_rejected"
	;;
nul)
	write_cfg
	append_cfg_mount <<CFG
mount {
	src: "/bin/true"
	dst: "/mnt/\000nul"
	is_bind: true
	is_dir: false
	rw: false
}
exec_bin {
	path: "/bin/sh"
	arg: "-c"
	arg: "echo CHILD_EXECUTED=yes"
}
CFG
	cmd=("$NSJAIL_BIN" -q -Mo --config "$CFG")
	outside_path=""
	inside_path=""
	expected="nul_rejected"
	;;
esac

if [ "$CASE_NAME" != "dynamic_content" ] && [ "$CASE_NAME" != "nul" ]; then
	echo "launcher=$(id)"
	if [ "$CLONE_PROFILE" = "disable_clone_newuser" ]; then
		echo "attacker_prevented=$(setpriv --reuid 1 --regid 1 --clear-groups bash --noprofile --norc -c 'if touch \"$PROTECTED/attacker_nope\" 2>/dev/null; then echo no; else echo yes; fi')"
	else
		echo "attacker_prevented=not-distinct-default-profile"
	fi
fi

echo "case=$CASE_NAME"
echo "backend=$BACKEND"
echo "profile=$PROFILE"
echo "clone_profile=$CLONE_PROFILE"
echo "expected=$expected"
echo "command=$(printf '%q ' "${cmd[@]}")"
if [ -n "${outside_path:-}" ]; then
	echo "outside_before=$(describe_path "$outside_path")"
fi
if [ -n "${inside_path:-}" ]; then
	echo "inside_before=$(describe_path "$inside_path")"
fi

set +e
"${cmd[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG"
rc=$?
set -e

if [ "${swapper_pid:-}" != "" ]; then
	wait "$swapper_pid"
fi

exit_code="$rc"
echo "exit_code=$exit_code"
if grep -q '^CHILD_EXECUTED=yes$' "$STDOUT_LOG"; then
	child_executed="yes"
else
	child_executed="no"
fi
echo "child_executed=$child_executed"
if [ -n "${outside_path:-}" ]; then
	outside_after="$(describe_path "$outside_path")"
	echo "outside_after=$outside_after"
fi
if [ -n "${inside_path:-}" ]; then
	inside_after="$(describe_path "$inside_path")"
	echo "inside_after=$inside_after"
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

expect_desc_contains() {
	local field="$1"
	local actual="$2"
	local want="$3"
	if [[ "$actual" != *"$want"* ]]; then
		echo "oracle_error=$field expected_substring=$want actual=$actual"
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

if [ "$PROFILE" = "patched" ]; then
	case "$CASE_NAME" in
	attack_mid_abs|attack_mid_rel)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_eq outside_after "${outside_after:-missing}" "missing"
		;;
	final_file|final_dir|loop|nondir|parentdot|nul)
		expect_eq exit_code "$exit_code" "255"
		expect_eq child_executed "$child_executed" "no"
		if [ -n "${outside_path:-}" ]; then
			expect_eq outside_after "${outside_after:-missing}" "missing"
		fi
		;;
	safe_final_file_bind)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "PATH_TYPE=symbolic link"
		expect_stdout_contains "TARGET_TYPE=regular"
		expect_stdout_contains "WRITE_BLOCKED"
		;;
	safe_final_dir_bind)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "PATH_TYPE=symbolic link"
		expect_stdout_contains "TARGET_TYPE=directory"
		expect_stdout_contains "WRITE_BLOCKED"
		;;
	safe_final_dir_tmpfs)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "PATH_TYPE=symbolic link"
		expect_stdout_contains "TARGET_TYPE=directory"
		expect_stdout_contains "WRITE_OK"
		;;
	bind_file)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "INSIDE_TYPE=regular file"
		;;
	bind_dir)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "INSIDE_TYPE=directory"
		expect_stdout_contains "WRITE_OK"
		expect_desc_contains outside_after "${outside_after:-}" "type=regular file"
		;;
	tmpfs|root_dot)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "INSIDE_TYPE=directory"
		expect_stdout_contains "WRITE_OK"
		;;
	dynamic_content)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_stdout_contains "INSIDE_TYPE=regular file"
		expect_stdout_contains "CONTENT=dynamic-content"
		;;
	symlink_dst|positive_abs|positive_rel|missing)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_desc_contains outside_after "${outside_after:-}" "type=symbolic link"
		expect_desc_contains outside_after "${outside_after:-}" "link=/bin/true"
		;;
	ro_src)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_eq outside_after "${outside_after:-missing}" "missing"
		expect_stdout_contains "WRITE_BLOCKED"
		;;
	race)
		expect_eq exit_code "$exit_code" "0"
		expect_eq child_executed "$child_executed" "yes"
		expect_eq outside_after "${outside_after:-missing}" "missing"
		expect_desc_contains inside_after "${inside_after:-}" "type=symbolic link"
		expect_desc_contains inside_after "${inside_after:-}" "link=/bin/true"
		;;
	esac
fi

if [ "$oracle_fail" -eq 0 ]; then
	echo "oracle_result=pass"
else
	echo "oracle_result=fail"
fi

printf '%s\n' '--- stdout ---'
cat "$STDOUT_LOG"
printf '%s\n' '--- stderr ---'
cat "$STDERR_LOG"
if [ -f "$STRACE_LOG" ]; then
	printf '%s\n' '--- strace ---'
	rg -n -C 4 'symlinkat\(|openat\(.*racedir|readlinkat\(|setresuid|setresgid|setgroups|prctl\(|mount\(|move_mount|mount_setattr' "$STRACE_LOG" || cat "$STRACE_LOG"
fi

if [ "$oracle_fail" -ne 0 ]; then
	exit 1
fi
EOF
