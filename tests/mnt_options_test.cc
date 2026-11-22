#include "mnt_options.h"

#include <stdint.h>
#include <sys/mount.h>

#include <string>

int main() {
	/* Default -B starts writable (flags = MS_BIND | MS_REC | MS_PRIVATE). */
	uintptr_t flags = MS_BIND | MS_REC | MS_PRIVATE;
	std::string fs_opts = mnt::extractGenericMountOptions("ro,noexec,nosuid,nodev", &flags);
	if (!fs_opts.empty()) return 1;
	if ((flags & (MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV)) !=
	    (MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV)) {
		return 2;
	}

	/* Filesystem-specific options survive while generic flags are extracted. */
	flags = 0;
	fs_opts =
	    mnt::extractGenericMountOptions("size=4194304,noexec,nosuid,mode=0755,ro", &flags);
	if (fs_opts != "size=4194304,mode=0755") return 3;
	if (flags != (MS_NOEXEC | MS_NOSUID | MS_RDONLY)) return 4;

	/* Later options override earlier flags cleanly (rw/exec/suid/dev). */
	flags = MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV;
	fs_opts = mnt::extractGenericMountOptions("rw,exec,suid,dev", &flags);
	if (!fs_opts.empty()) return 5;
	if (flags != 0) return 6;

	/* Empty tokens and unknown fs options are handled without corruption. */
	flags = 0;
	fs_opts = mnt::extractGenericMountOptions(",ro,,nr_inodes=1024,nodev,", &flags);
	if (fs_opts != "nr_inodes=1024") return 7;
	if (flags != (MS_RDONLY | MS_NODEV)) return 8;

	return 0;
}
