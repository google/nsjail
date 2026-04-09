/*

   nsjail - missing definitions used across the code
   -----------------------------------------

   Copyright 2026 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef NS_MISSING_DEFS_H
#define NS_MISSING_DEFS_H

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#if __has_include(<linux/close_range.h>)
#include <linux/close_range.h>
#endif
#if __has_include(<linux/mount.h>)
#include <linux/mount.h>
#endif

/* =========================================================================
 * Syscall numbers
 * ========================================================================= */

/*
 * __NR_pidfd_send_signal - send a signal to a process via pidfd  (Linux 5.1)
 */
#if !defined(__NR_pidfd_send_signal)
#if defined(__x86_64__)
#define __NR_pidfd_send_signal 424
#elif defined(__i386__)
#define __NR_pidfd_send_signal 424
#elif defined(__aarch64__)
#define __NR_pidfd_send_signal 424
#elif defined(__arm__)
#define __NR_pidfd_send_signal 424
#elif defined(__riscv)
#define __NR_pidfd_send_signal 424
#elif defined(__mips__) && defined(__LP64__)
#define __NR_pidfd_send_signal (5000 + 424)
#elif defined(__mips__)
#define __NR_pidfd_send_signal (4000 + 424)
#elif defined(__m68k__)
#define __NR_pidfd_send_signal 424
#else
#error "Unsupported architecture for __NR_pidfd_send_signal"
#endif
#endif /* !defined(__NR_pidfd_send_signal) */

/*
 * __NR_clone3 - create a new process with extended clone_args  (Linux 5.3)
 */
#if !defined(__NR_clone3)
#if defined(__x86_64__)
#define __NR_clone3 435
#elif defined(__i386__)
#define __NR_clone3 435
#elif defined(__aarch64__)
#define __NR_clone3 435
#elif defined(__arm__)
#define __NR_clone3 435
#elif defined(__riscv)
#define __NR_clone3 435
#elif defined(__mips__) && defined(__LP64__)
#define __NR_clone3 (5000 + 435)
#elif defined(__mips__)
#define __NR_clone3 (4000 + 435)
#elif defined(__m68k__)
#define __NR_clone3 435
#else
#error "Unsupported architecture for __NR_clone3"
#endif
#endif /* !defined(__NR_clone3) */

/*
 * __NR_close_range - close a range of file descriptors  (Linux 5.9)
 */
#if !defined(__NR_close_range)
#if defined(__x86_64__)
#define __NR_close_range 436
#elif defined(__i386__)
#define __NR_close_range 436
#elif defined(__aarch64__)
#define __NR_close_range 436
#elif defined(__arm__)
#define __NR_close_range 436
#elif defined(__riscv)
#define __NR_close_range 436
#elif defined(__mips__) && defined(__LP64__)
#define __NR_close_range (5000 + 436)
#elif defined(__mips__)
#define __NR_close_range (4000 + 436)
#elif defined(__m68k__)
#define __NR_close_range 436
#else
#error "Unsupported architecture for __NR_close_range"
#endif
#endif /* !defined(__NR_close_range) */

/*
 * __NR_pidfd_open - obtain a pidfd for a given PID  (Linux 5.3)
 */
#if !defined(__NR_pidfd_open)
#if defined(__x86_64__)
#define __NR_pidfd_open 434
#elif defined(__i386__)
#define __NR_pidfd_open 434
#elif defined(__aarch64__)
#define __NR_pidfd_open 434
#elif defined(__arm__)
#define __NR_pidfd_open 434
#elif defined(__riscv)
#define __NR_pidfd_open 434
#elif defined(__mips__) && defined(__LP64__)
#define __NR_pidfd_open (5000 + 434)
#elif defined(__mips__)
#define __NR_pidfd_open (4000 + 434)
#elif defined(__m68k__)
#define __NR_pidfd_open 434
#else
#error "Unsupported architecture for __NR_pidfd_open"
#endif
#endif /* !defined(__NR_pidfd_open) */

/*
 * __NR_seccomp - seccomp system call  (Linux 3.17)
 */
#if !defined(__NR_seccomp)
#if defined(__x86_64__)
#define __NR_seccomp 317
#elif defined(__i386__)
#define __NR_seccomp 354
#elif defined(__aarch64__)
#define __NR_seccomp 277
#elif defined(__arm__)
#define __NR_seccomp 383
#elif defined(__riscv)
#define __NR_seccomp 277
#elif defined(__mips__) && defined(__LP64__)
#define __NR_seccomp (5000 + 312)
#elif defined(__mips__)
#define __NR_seccomp (4000 + 352)
#elif defined(__m68k__)
#define __NR_seccomp 380
#else
#error "Unsupported architecture for __NR_seccomp"
#endif
#endif /* !defined(__NR_seccomp) */

/*
 * __NR_getrandom - obtain random bytes  (Linux 3.17)
 */
#if !defined(__NR_getrandom)
#if defined(__x86_64__)
#define __NR_getrandom 318
#elif defined(__i386__)
#define __NR_getrandom 355
#elif defined(__aarch64__)
#define __NR_getrandom 278
#elif defined(__arm__)
#define __NR_getrandom 384
#elif defined(__riscv)
#define __NR_getrandom 278
#elif defined(__mips__) && defined(__LP64__)
#define __NR_getrandom 5313
#elif defined(__mips__)
#define __NR_getrandom 4353
#elif defined(__m68k__)
#define __NR_getrandom 352
#else
#error "Unsupported architecture for __NR_getrandom"
#endif
#endif /* !defined(__NR_getrandom) */

/*
 * __NR_memfd_create - create anonymous file backed by memory  (Linux 3.17)
 */
#if !defined(__NR_memfd_create)
#if defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#elif defined(__aarch64__)
#define __NR_memfd_create 279
#elif defined(__arm__)
#define __NR_memfd_create 385
#elif defined(__riscv)
#define __NR_memfd_create 279
#elif defined(__mips__) && defined(__LP64__)
#define __NR_memfd_create 5314
#elif defined(__mips__)
#define __NR_memfd_create 4354
#elif defined(__m68k__)
#define __NR_memfd_create 353
#else
#error "Unsupported architecture for __NR_memfd_create"
#endif
#endif /* !defined(__NR_memfd_create) */

/*
 * __NR_execveat - execute program relative to a directory fd  (Linux 3.19)
 */
#if !defined(__NR_execveat)
#if defined(__x86_64__)
#define __NR_execveat 322
#elif defined(__i386__)
#define __NR_execveat 358
#elif defined(__aarch64__)
#define __NR_execveat 281
#elif defined(__arm__)
#define __NR_execveat 387
#elif defined(__riscv)
#define __NR_execveat 281
#elif defined(__mips__) && defined(__LP64__)
#define __NR_execveat 5316
#elif defined(__mips__)
#define __NR_execveat 4356
#elif defined(__m68k__)
#define __NR_execveat 355
#else
#error "Unsupported architecture for __NR_execveat"
#endif
#endif /* !defined(__NR_execveat) */

/*
 * __NR_pidfd_getfd - get a file descriptor from another process  (Linux 5.6)
 */
#if !defined(__NR_pidfd_getfd)
#if defined(__x86_64__)
#define __NR_pidfd_getfd 438
#elif defined(__i386__)
#define __NR_pidfd_getfd 438
#elif defined(__aarch64__)
#define __NR_pidfd_getfd 438
#elif defined(__arm__)
#define __NR_pidfd_getfd 438
#elif defined(__riscv)
#define __NR_pidfd_getfd 438
#elif defined(__mips__) && defined(__LP64__)
#define __NR_pidfd_getfd (5000 + 438)
#elif defined(__mips__)
#define __NR_pidfd_getfd (4000 + 438)
#elif defined(__m68k__)
#define __NR_pidfd_getfd 438
#else
#error "Unsupported architecture for __NR_pidfd_getfd"
#endif
#endif /* !defined(__NR_pidfd_getfd) */

/* =========================================================================
 * clone / unshare flags
 * ========================================================================= */

#if !defined(CLONE_PIDFD)
#define CLONE_PIDFD 0x00001000
#endif

#if !defined(CLONE_NEWTIME)
#define CLONE_NEWTIME 0x00000080
#endif

#if !defined(CLONE_NEWCGROUP)
#define CLONE_NEWCGROUP 0x02000000
#endif

#if !defined(CLONE_CLEAR_SIGHAND)
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

#if !defined(CLONE_INTO_CGROUP)
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/* =========================================================================
 * close_range flags
 * ========================================================================= */

#if !defined(CLOSE_RANGE_UNSHARE)
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

#if !defined(CLOSE_RANGE_CLOEXEC)
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

/* =========================================================================
 * New mount API syscall numbers (Linux 5.2+)
 *
 * These all use the generic syscall table and share the same number on
 * every architecture, except MIPS which adds a per-ABI base offset.
 * ========================================================================= */

#if !defined(__NR_open_tree)
#if defined(__mips__) && defined(__LP64__)
#define __NR_open_tree (5000 + 428)
#elif defined(__mips__)
#define __NR_open_tree (4000 + 428)
#else
#define __NR_open_tree 428
#endif
#endif

#if !defined(__NR_move_mount)
#if defined(__mips__) && defined(__LP64__)
#define __NR_move_mount (5000 + 429)
#elif defined(__mips__)
#define __NR_move_mount (4000 + 429)
#else
#define __NR_move_mount 429
#endif
#endif

#if !defined(__NR_fsopen)
#if defined(__mips__) && defined(__LP64__)
#define __NR_fsopen (5000 + 430)
#elif defined(__mips__)
#define __NR_fsopen (4000 + 430)
#else
#define __NR_fsopen 430
#endif
#endif

#if !defined(__NR_fsconfig)
#if defined(__mips__) && defined(__LP64__)
#define __NR_fsconfig (5000 + 431)
#elif defined(__mips__)
#define __NR_fsconfig (4000 + 431)
#else
#define __NR_fsconfig 431
#endif
#endif

#if !defined(__NR_fsmount)
#if defined(__mips__) && defined(__LP64__)
#define __NR_fsmount (5000 + 432)
#elif defined(__mips__)
#define __NR_fsmount (4000 + 432)
#else
#define __NR_fsmount 432
#endif
#endif

#if !defined(__NR_mount_setattr)
#if defined(__mips__) && defined(__LP64__)
#define __NR_mount_setattr (5000 + 442)
#elif defined(__mips__)
#define __NR_mount_setattr (4000 + 442)
#else
#define __NR_mount_setattr 442
#endif
#endif

/* =========================================================================
 * New mount API constants and types
 * ========================================================================= */

#if !defined(FSOPEN_CLOEXEC)
#define FSOPEN_CLOEXEC 0x00000001
#endif

#if !defined(FSMOUNT_CLOEXEC)
#define FSMOUNT_CLOEXEC 0x00000001
#endif

#if !defined(OPEN_TREE_CLONE)
#define OPEN_TREE_CLONE 1
#endif

#if !defined(OPEN_TREE_CLOEXEC)
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

#if !defined(MOVE_MOUNT_F_EMPTY_PATH)
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#if !defined(MOUNT_ATTR_RDONLY)
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#if !defined(MOUNT_ATTR_NOSUID)
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#if !defined(MOUNT_ATTR_NODEV)
#define MOUNT_ATTR_NODEV 0x00000004
#endif

#if !defined(MOUNT_ATTR_NOEXEC)
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

/*
 * FSCONFIG_* are enum values in <linux/mount.h>, not #defines.
 * We cannot use #if !defined() for enums, so we gate on a #define
 * that was introduced in the same header version (MOUNT_ATTR_RDONLY
 * was already handled above; we use MOUNT_ATTR_SIZE_VER0 as a proxy
 * for "the header defined the full new mount API").
 */
#if !defined(MOUNT_ATTR_SIZE_VER0)
enum {
	FSCONFIG_SET_FLAG = 0,
	FSCONFIG_SET_STRING = 1,
	FSCONFIG_SET_BINARY = 2,
	FSCONFIG_SET_PATH = 3,
	FSCONFIG_SET_PATH_EMPTY = 4,
	FSCONFIG_SET_FD = 5,
	FSCONFIG_CMD_CREATE = 6,
	FSCONFIG_CMD_RECONFIGURE = 7,
};

#define MOUNT_ATTR_SIZE_VER0 32

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif /* !defined(MOUNT_ATTR_SIZE_VER0) */

/* =========================================================================
 * fcntl / AT_* flags
 * ========================================================================= */

#if !defined(AT_EMPTY_PATH)
#define AT_EMPTY_PATH 0x1000
#endif

#if !defined(AT_RECURSIVE)
#define AT_RECURSIVE 0x8000
#endif

/* =========================================================================
 * Mount flags
 * ========================================================================= */

#if !defined(MS_NOSYMFOLLOW)
#define MS_NOSYMFOLLOW 256
#endif /* if !defined(MS_NOSYMFOLLOW) */

#if !defined(MS_LAZYTIME)
#define MS_LAZYTIME (1 << 25)
#endif /* if !defined(MS_LAZYTIME) */

#if !defined(MS_ACTIVE)
#define MS_ACTIVE (1 << 30)
#endif /* if !defined(MS_ACTIVE) */

#if !defined(MS_NOUSER)
#define MS_NOUSER (1 << 31)
#endif /* if !defined(MS_NOUSER) */

#if !defined(ST_NOSYMFOLLOW)
#define ST_NOSYMFOLLOW 8192
#endif /* if !defined(ST_NOSYMFOLLOW) */

/* =========================================================================
 * PR_SET_* flags
 * ========================================================================= */

#if !defined(PR_SET_NO_NEW_PRIVS)
#define PR_SET_NO_NEW_PRIVS 38
#endif /* PR_SET_NO_NEW_PRIVS */

#if !defined(PR_CAP_AMBIENT)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif /* !defined(PR_CAP_AMBIENT) */

/* =========================================================================
 * SECCOMP_FILTER_FLAG_* flags
 * ========================================================================= */

#if !defined(SECCOMP_FILTER_FLAG_TSYNC)
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif /* SECCOMP_FILTER_FLAG_TSYNC */

#if !defined(SECCOMP_FILTER_FLAG_LOG)
#define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif /* SECCOMP_FILTER_FLAG_LOG */

#if !defined(SECCOMP_FILTER_FLAG_NEW_LISTENER)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif /* SECCOMP_FILTER_FLAG_NEW_LISTENER */

/* =========================================================================
 * CAP_* capabilities
 * ========================================================================= */

#if !defined(CAP_AUDIT_READ)
#define CAP_AUDIT_READ 37
#endif /* !defined(CAP_AUDIT_READ) */

#if !defined(CAP_PERFMON)
#define CAP_PERFMON 38
#endif /* !defined(CAP_PERFMON) */

#if !defined(CAP_BPF)
#define CAP_BPF 39
#endif /* !defined(CAP_BPF) */

#if !defined(CAP_CHECKPOINT_RESTORE)
#define CAP_CHECKPOINT_RESTORE 40
#endif /* !defined(CAP_CHECKPOINT_RESTORE) */

/* =========================================================================
 * struct rlimit64
 * ========================================================================= */

#if !defined(RLIM64_INFINITY)
#define RLIM64_INFINITY (~0ULL)
struct rlimit64 {
	uint64_t rlim_cur;
	uint64_t rlim_max;
};
#endif /* !defined(RLIM64_INFINITY) */

#endif /* NS_MISSING_DEFS_H */
