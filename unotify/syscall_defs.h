#ifndef NSJAIL_UNOTIFY_SYSCALL_DEFS_H
#define NSJAIL_UNOTIFY_SYSCALL_DEFS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/syscall.h>

namespace unotify {



enum class SyscallCategory : uint8_t {
	FS,
	NET,
};

/*
 * Describes the role of each syscall argument for automatic decoding.
 *
 * The generic decoder processes args[0..5] left-to-right, maintaining:
 *   current_dirfd    - set by DIRFD, consumed+reset by PATH
 *   last_socket_type - set by FD, consumed by SADDR
 *   last_path        - set by PATH, consumed by FLAGS/OHOW
 */
enum class ArgRole : uint8_t {
	SKIP,    /* Don't decode this argument */
	PATH,    /* String ptr -> populatePathInfo (alternates path1/path2) */
	DIRFD,   /* Directory fd; sets context for next PATH */
	FLAGS,   /* Open flags -> getFileMode on last populated path */
	OCTAL,   /* Permission mode -> "mode=0NNN" */
	ACCESS,  /* Access mode -> "mode=R_OK|W_OK|X_OK" */
	UID,     /* User id -> "owner=N" */
	GID,     /* Group id -> "group=N" */
	ARGV,    /* String array ptr -> "argv[i]=..." */
	ENVP,    /* String array ptr -> "envp[i]=..." */
	FD,      /* Socket fd -> "fd=N" + getSocketType */
	SADDR,   /* sockaddr ptr; next arg must be ALEN */
	ALEN,    /* sockaddr length; consumed by preceding SADDR */
	IFLAGS,  /* Integer flags -> "flags=N" */

	DOMAIN,  /* Socket domain -> getDomainStr */
	STYPE,   /* Socket type -> getTypeStr */
	PROTO,   /* Protocol -> getProtocolStr */
	OHOW,    /* struct open_how ptr -> decode flags + resolve */
};

struct SyscallDef {
	int nr;                    /* __NR_xxx */
	const char* kafel_name;    /* name for kafel policy ("newstat", "sendmsg") */
	const char* display_name;  /* name for stats output ("stat", "sendmsg") */
	SyscallCategory category;
	ArgRole args[6];           /* role of each syscall argument */
};

/* Shorthand for table readability */
using A = ArgRole;

/*
 * THE SINGLE SOURCE OF TRUTH for which syscalls are traced via seccomp unotify.
 *
 * To add a new traced syscall: add one entry here.
 * The kafel BPF policy, name lookup, and argument decoding all derive from this table.
 */
static constexpr SyscallDef kTracedSyscalls[] = {
	/* FS - arg0 = path (AT_FDCWD implied) */
	{__NR_open, "open", "open", SyscallCategory::FS,
	    {A::PATH, A::FLAGS, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_stat, "newstat", "stat", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_lstat, "newlstat", "lstat", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_access, "access", "access", SyscallCategory::FS,
	    {A::PATH, A::ACCESS, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_chmod, "chmod", "chmod", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_chown, "chown", "chown", SyscallCategory::FS,
	    {A::PATH, A::UID, A::GID, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_lchown, "lchown", "lchown", SyscallCategory::FS,
	    {A::PATH, A::UID, A::GID, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_readlink, "readlink", "readlink", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_mkdir, "mkdir", "mkdir", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_mknod, "mknod", "mknod", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_rmdir, "rmdir", "rmdir", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_unlink, "unlink", "unlink", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_execve, "execve", "execve", SyscallCategory::FS,
	    {A::PATH, A::ARGV, A::ENVP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_chdir, "chdir", "chdir", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_chroot, "chroot", "chroot", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},

	/* FS - arg0 = dirfd, arg1 = path */
	{__NR_openat, "openat", "openat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::FLAGS, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_openat2, "openat2", "openat2", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OHOW, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_newfstatat, "newfstatat", "newfstatat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_faccessat, "faccessat", "faccessat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::ACCESS, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_fchmodat, "fchmodat", "fchmodat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_fchownat, "fchownat", "fchownat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::UID, A::GID, A::SKIP, A::SKIP}},
	{__NR_readlinkat, "readlinkat", "readlinkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_mkdirat, "mkdirat", "mkdirat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_mknodat, "mknodat", "mknodat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_unlinkat, "unlinkat", "unlinkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_execveat, "execveat", "execveat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::ARGV, A::ENVP, A::SKIP, A::SKIP}},

	/* FS - two paths */
	{__NR_rename, "rename", "rename", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_link, "link", "link", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_symlink, "symlink", "symlink", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},

	/* FS - two dirfd+path pairs */
	{__NR_renameat, "renameat", "renameat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},
	{__NR_renameat2, "renameat2", "renameat2", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},
	{__NR_linkat, "linkat", "linkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},

	/* symlinkat: arg0=target(CWD), arg1=newdirfd, arg2=newpath */
	{__NR_symlinkat, "symlinkat", "symlinkat", SyscallCategory::FS,
	    {A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP}},

	/* NET - sockaddr-based */
	{__NR_connect, "connect", "connect", SyscallCategory::NET,
	    {A::FD, A::SADDR, A::ALEN, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_bind, "bind", "bind", SyscallCategory::NET,
	    {A::FD, A::SADDR, A::ALEN, A::SKIP, A::SKIP, A::SKIP}},
	{__NR_sendto, "sendto", "sendto", SyscallCategory::NET,
	    {A::FD, A::SKIP, A::SKIP, A::IFLAGS, A::SADDR, A::ALEN}},

	/* NET - socket creation */
	{__NR_socket, "socket", "socket", SyscallCategory::NET,
	    {A::DOMAIN, A::STYPE, A::PROTO, A::SKIP, A::SKIP, A::SKIP}},
};

constexpr size_t kTracedSyscallCount = sizeof(kTracedSyscalls) / sizeof(kTracedSyscalls[0]);

/*
 * Build the kafel policy string from the table.
 * Called by sandbox.cc - no manual syscall list maintenance needed.
 */
inline std::string buildKafelPolicy() {
	std::string p = "POLICY unotify {\n  USER_NOTIF {\n";
	for (size_t i = 0; i < kTracedSyscallCount; i++) {
		if (i > 0) p += ", ";
		p += kTracedSyscalls[i].kafel_name;
	}
	p += "\n  }\n}\nUSE unotify DEFAULT ALLOW\n";
	return p;
}

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_SYSCALL_DEFS_H */
