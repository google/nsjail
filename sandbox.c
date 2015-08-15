/*

   nsjail - seccomp-bpf sandboxing
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

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

#include "sandbox.h"

#include <errno.h>
#include <sys/prctl.h>

/* TBREMOVED */
#include <signal.h>
#include <unistd.h>

#include "common.h"
#include "log.h"

#if defined(__x86_64__) || defined(__i386__)
#include "seccomp/bpf-helper.h"

/*
 * A demo policy, it disallows syslog and ptrace syscalls, both in 32 and 64
 * modes
 */
static bool sandboxPrepareAndCommit(void)
{
	struct bpf_labels l = {.count = 0 };
	struct sock_filter filter[] = {
		LOAD_ARCH,
		JEQ32(AUDIT_ARCH_I386, JUMP(&l, label_i386)),
		JEQ32(AUDIT_ARCH_X86_64, JUMP(&l, label_x86_64)),

		/* I386 */
		LABEL(&l, label_i386),
		LOAD_SYSCALL_NR,
#define __NR_syslog_32 103
#define __NR_uselib_32 86
		JEQ32(__NR_syslog_32, ERRNO(ENOENT)),
		JEQ32(__NR_uselib_32, ERRNO(ENOENT)),
		ALLOW,

		/* X86_64 */
		LABEL(&l, label_x86_64),
		LOAD_SYSCALL_NR,
#define __NR_syslog_64 103
#define __NR_uselib_64 134
		JEQ32(__NR_syslog_64, ERRNO(ENOENT)),
		JEQ32(__NR_uselib_64, ERRNO(ENOENT)),
		ALLOW,
	};

	struct sock_fprog prog = {
		.filter = filter,
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
	};
	if (bpf_resolve_jumps(&l, filter, sizeof(filter) / sizeof(*filter)) != 0) {
		LOG_W("bpf_resolve_jumps() failed");
		return false;
	}
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif				/* PR_SET_NO_NEW_PRIVS */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		PLOG_W("prctl(PR_SET_NO_NEW_PRIVS, 1) failed");
		return false;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)) {
		PLOG_W("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed");
		return false;
	}
	return true;
}
#endif				/* defined(__x86_64__) || defined(__i386__) */

bool sandboxApply(struct nsjconf_t * nsjconf)
{
	if (nsjconf->apply_sandbox == false) {
		return true;
	}
#if defined(__x86_64__) || defined(__i386__)
	if (sandboxPrepareAndCommit() == false) {
		return false;
	}
#else				/* defined(__x86_64__) || defined(__i386__) */
	LOG_W
	    ("There's no seccomp-bpf implementation ready for the current CPU architecture. Sandbox not enabled");
#endif				/* defined(__x86_64__) || defined(__i386__) */
	return true;
}
