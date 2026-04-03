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
#ifdef __NR_open
	{__NR_open, "open", "open", SyscallCategory::FS,
	    {A::PATH, A::FLAGS, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_open */
#ifdef __NR_stat
	{__NR_stat, "newstat", "stat", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_stat */
#ifdef __NR_lstat
	{__NR_lstat, "newlstat", "lstat", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_lstat */
#ifdef __NR_access
	{__NR_access, "access", "access", SyscallCategory::FS,
	    {A::PATH, A::ACCESS, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_access */
#ifdef __NR_chmod
	{__NR_chmod, "chmod", "chmod", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_chmod */
#ifdef __NR_chown
	{__NR_chown, "chown", "chown", SyscallCategory::FS,
	    {A::PATH, A::UID, A::GID, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_chown */
#ifdef __NR_lchown
	{__NR_lchown, "lchown", "lchown", SyscallCategory::FS,
	    {A::PATH, A::UID, A::GID, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_lchown */
#ifdef __NR_readlink
	{__NR_readlink, "readlink", "readlink", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_readlink */
#ifdef __NR_mkdir
	{__NR_mkdir, "mkdir", "mkdir", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_mkdir */
#ifdef __NR_mknod
	{__NR_mknod, "mknod", "mknod", SyscallCategory::FS,
	    {A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_mknod */
#ifdef __NR_rmdir
	{__NR_rmdir, "rmdir", "rmdir", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_rmdir */
#ifdef __NR_unlink
	{__NR_unlink, "unlink", "unlink", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_unlink */
#ifdef __NR_execve
	{__NR_execve, "execve", "execve", SyscallCategory::FS,
	    {A::PATH, A::ARGV, A::ENVP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_execve */
#ifdef __NR_chdir
	{__NR_chdir, "chdir", "chdir", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_chdir */
#ifdef __NR_chroot
	{__NR_chroot, "chroot", "chroot", SyscallCategory::FS,
	    {A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_chroot */

	/* FS - arg0 = dirfd, arg1 = path */
#ifdef __NR_openat
	{__NR_openat, "openat", "openat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::FLAGS, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_openat */
#ifdef __NR_openat2
	{__NR_openat2, "openat2", "openat2", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OHOW, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_openat2 */
#ifdef __NR_newfstatat
	{__NR_newfstatat, "newfstatat", "newfstatat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_newfstatat */
#ifdef __NR_faccessat
	{__NR_faccessat, "faccessat", "faccessat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::ACCESS, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_faccessat */
#ifdef __NR_fchmodat
	{__NR_fchmodat, "fchmodat", "fchmodat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_fchmodat */
#ifdef __NR_fchownat
	{__NR_fchownat, "fchownat", "fchownat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::UID, A::GID, A::SKIP, A::SKIP}},
#endif /* __NR_fchownat */
#ifdef __NR_readlinkat
	{__NR_readlinkat, "readlinkat", "readlinkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_readlinkat */
#ifdef __NR_mkdirat
	{__NR_mkdirat, "mkdirat", "mkdirat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_mkdirat */
#ifdef __NR_mknodat
	{__NR_mknodat, "mknodat", "mknodat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::OCTAL, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_mknodat */
#ifdef __NR_unlinkat
	{__NR_unlinkat, "unlinkat", "unlinkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_unlinkat */
#ifdef __NR_execveat
	{__NR_execveat, "execveat", "execveat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::ARGV, A::ENVP, A::SKIP, A::SKIP}},
#endif /* __NR_execveat */

	/* FS - two paths */
#ifdef __NR_rename
	{__NR_rename, "rename", "rename", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_rename */
#ifdef __NR_link
	{__NR_link, "link", "link", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_link */
#ifdef __NR_symlink
	{__NR_symlink, "symlink", "symlink", SyscallCategory::FS,
	    {A::PATH, A::PATH, A::SKIP, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_symlink */

	/* FS - two dirfd+path pairs */
#ifdef __NR_renameat
	{__NR_renameat, "renameat", "renameat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},
#endif /* __NR_renameat */
#ifdef __NR_renameat2
	{__NR_renameat2, "renameat2", "renameat2", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},
#endif /* __NR_renameat2 */
#ifdef __NR_linkat
	{__NR_linkat, "linkat", "linkat", SyscallCategory::FS,
	    {A::DIRFD, A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP}},
#endif /* __NR_linkat */

	/* symlinkat: arg0=target(CWD), arg1=newdirfd, arg2=newpath */
#ifdef __NR_symlinkat
	{__NR_symlinkat, "symlinkat", "symlinkat", SyscallCategory::FS,
	    {A::PATH, A::DIRFD, A::PATH, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_symlinkat */

	/* NET - sockaddr-based */
#ifdef __NR_connect
	{__NR_connect, "connect", "connect", SyscallCategory::NET,
	    {A::FD, A::SADDR, A::ALEN, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_connect */
#ifdef __NR_bind
	{__NR_bind, "bind", "bind", SyscallCategory::NET,
	    {A::FD, A::SADDR, A::ALEN, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_bind */
#ifdef __NR_sendto
	{__NR_sendto, "sendto", "sendto", SyscallCategory::NET,
	    {A::FD, A::SKIP, A::SKIP, A::IFLAGS, A::SADDR, A::ALEN}},
#endif /* __NR_sendto */

	/* NET - socket creation */
#ifdef __NR_socket
	{__NR_socket, "socket", "socket", SyscallCategory::NET,
	    {A::DOMAIN, A::STYPE, A::PROTO, A::SKIP, A::SKIP, A::SKIP}},
#endif /* __NR_socket */
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
