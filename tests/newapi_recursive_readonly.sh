#!/bin/sh
# Integration regression for the new mount API's recursive read-only bind mounts.
# Requires Linux >= 6.3, root/CAP_SYS_ADMIN, and a usable mount namespace.
# Run directly or through: make test-newapi-recursive-readonly
set -eu

if [ "${NSJAIL_NEWAPI_MOUNT_NS:-}" != 1 ]; then
    if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] ||
        ! unshare --mount --propagation private true 2>/dev/null; then
        echo "SKIP: requires Linux, root/CAP_SYS_ADMIN and mount namespaces"
        exit 77
    fi
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)
    if [ "$kernel_major" -lt 6 ] ||
        { [ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -lt 3 ]; }; then
        echo "SKIP: requires Linux >= 6.3"
        exit 77
    fi
    exec unshare --mount --propagation private env NSJAIL_NEWAPI_MOUNT_NS=1 "$0" "$@"
fi

nsjail_bin=${1:-./nsjail}
src=$(mktemp -d "${TMPDIR:-/tmp}/nsjail-newapi-ro.XXXXXXXX")
child=$(mktemp -d "${TMPDIR:-/tmp}/nsjail-newapi-child.XXXXXXXX")
cleanup() {
    umount "$child/nested" 2>/dev/null || :
    umount "$src/nested" 2>/dev/null || :
    rm -rf "$child" "$src"
}
trap cleanup EXIT HUP INT TERM

mkdir "$src/nested"
printf 'ordinary\n' > "$src/ordinary-file"
mount -t tmpfs -o size=4m tmpfs "$src/nested"
printf 'nested\n' > "$src/nested/nested-file"
mountpoint -q "$src/nested"

# --rw makes is_root_rw=true; --experimental_mnt=new forces the new API.
# Disable unrelated namespaces so the test isolates mount behavior.
for mode in ro rw; do
    if [ "$mode" = ro ]; then
        bind_arg=-R
    else
        bind_arg=-B
    fi

    "$nsjail_bin" --experimental_mnt=new -q -Mo --rw \
        -R /usr:/usr -s /usr/lib:/lib -s /usr/lib64:/lib64 \
        --disable_clone_newuser --disable_clone_newnet \
        --disable_clone_newcgroup \
        "$bind_arg" "$src:/tmp/nsjail-newapi-check" -- \
        /usr/bin/sh -c '
            set -eu
            dest=/tmp/nsjail-newapi-check
            mode=$1
            test -f "$dest/ordinary-file"
            test -f "$dest/nested/nested-file"
            touch /tmp/nsjail-newapi-root-writable
            rm /tmp/nsjail-newapi-root-writable

            for target in "$dest" "$dest/nested"; do
                opts=$(findmnt -n -o VFS-OPTIONS -T "$target")
                echo "$mode $target $opts"
                case ",$opts," in
                    *,ro,*) state=ro ;;
                    *,rw,*) state=rw ;;
                    *) echo "FAIL: no ro/rw VFS flag for $target" >&2; exit 1 ;;
                esac
                if [ "$state" != "$mode" ]; then
                    echo "FAIL: $target is $state, expected $mode" >&2
                    exit 1
                fi
                if touch "$target/nsjail-369-probe" 2>/tmp/nsjail-newapi-probe.err; then
                    if [ "$mode" = ro ]; then
                        echo "FAIL: write succeeded on read-only $target" >&2
                        exit 1
                    fi
                    rm "$target/nsjail-369-probe"
                elif [ "$mode" = rw ]; then
                    echo "FAIL: write rejected on writable $target" >&2
                    exit 1
                fi
            done
        ' sh "$mode"
done

# A later writable recursive bind must be stageable beneath a read-only bind.
# Its independently cloned nested mounts must remain writable (not inherited
# from the earlier read-only parent). The destination intentionally does not
# exist in the source before nsjail constructs the mount tree.
mkdir "$child/nested"
mount -t tmpfs -o size=4m tmpfs "$child/nested"
printf 'child\n' > "$child/nested/nested-file"
test ! -e "$src/newchild"
"$nsjail_bin" --experimental_mnt=new -q -Mo --rw \
    -R /usr:/usr -s /usr/lib:/lib -s /usr/lib64:/lib64 \
    --disable_clone_newuser --disable_clone_newnet \
    --disable_clone_newcgroup \
    -R "$src:/tmp/nsjail-newapi-check" \
    -B "$child:/tmp/nsjail-newapi-check/newchild" -- \
    /usr/bin/sh -c '
        set -eu
        parent=/tmp/nsjail-newapi-check
        child="$parent/newchild"
        test -f "$child/nested/nested-file"
        for entry in "ro:$parent" "ro:$parent/nested" \
                     "rw:$child" "rw:$child/nested"; do
            expected=${entry%%:*}
            target=${entry#*:}
            opts=$(findmnt -n -o VFS-OPTIONS -T "$target")
            echo "override $expected $target $opts"
            case ",$opts," in
                *,ro,*) actual=ro ;;
                *,rw,*) actual=rw ;;
                *) echo "FAIL: no mount VFS state on $target" >&2; exit 1 ;;
            esac
            if [ "$actual" != "$expected" ]; then
                echo "FAIL: $target is $actual, expected $expected" >&2
                exit 1
            fi
            if touch "$target/nsjail-369-override" 2>/tmp/nsjail-newapi-probe.err; then
                if [ "$expected" = ro ]; then
                    echo "FAIL: write succeeded on read-only $target" >&2
                    exit 1
                fi
                rm "$target/nsjail-369-override"
            elif [ "$expected" = rw ]; then
                echo "FAIL: write failed on writable $target" >&2
                exit 1
            fi
        done
    '

# File bind with no nested submounts must still be read-only.
"$nsjail_bin" --experimental_mnt=new -q -Mo --rw \
    -R /usr:/usr -s /usr/lib:/lib -s /usr/lib64:/lib64 \
    --disable_clone_newuser --disable_clone_newnet \
    --disable_clone_newcgroup \
    -R "$src/ordinary-file:/tmp/nsjail-newapi-file" -- \
    /usr/bin/sh -c '
        set -eu
        test -f /tmp/nsjail-newapi-file
        opts=$(findmnt -n -o VFS-OPTIONS -T /tmp/nsjail-newapi-file)
        echo "ro-file $opts"
        case ",$opts," in *,ro,*) : ;; *) exit 1 ;; esac
        if touch /tmp/nsjail-newapi-file 2>/tmp/nsjail-newapi-probe.err; then
            echo "FAIL: read-only file bind was writable" >&2
            exit 1
        fi
    '

echo "PASS: recursive ro/rw, later writable nested child, and file-bind ro"
