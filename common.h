/*

   nsjail - common structures
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

#ifndef _COMMON_H
#define _COMMON_H

#include <limits.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/types.h>

#define ARRAYSIZE(array) (sizeof(array) / sizeof(*array))

struct pids_t {
	pid_t pid;
	time_t start;
	char remote_txt[64];
	struct sockaddr_in6 remote_addr;
	 LIST_ENTRY(pids_t) pointers;
};

struct mounts_t {
	const char *src;
	const char *dst;
	const char *fs_type;
	const char *options;
	uintptr_t flags;
	 LIST_ENTRY(mounts_t) pointers;
};

enum mode_t {
	MODE_LISTEN_TCP = 0,
	MODE_STANDALONE_ONCE,
	MODE_STANDALONE_EXECVE,
	MODE_STANDALONE_RERUN
};

struct nsjconf_t {
	const char *hostname;
	const char *cwd;
	char *const *argv;
	int port;
	uid_t uid;
	gid_t gid;
	bool daemonize;
	time_t tlimit;
	bool apply_sandbox;
	bool verbose;
	bool keep_env;
	bool keep_caps;
	rlim64_t rl_as;
	rlim64_t rl_core;
	rlim64_t rl_cpu;
	rlim64_t rl_fsize;
	rlim64_t rl_nofile;
	rlim64_t rl_nproc;
	rlim64_t rl_stack;
	unsigned long personality;
	bool clone_newnet;
	bool clone_newuser;
	bool clone_newns;
	bool clone_newpid;
	bool clone_newipc;
	bool clone_newuts;
	enum mode_t mode;
	const char *chroot;
	bool is_root_rw;
	bool is_silent;
	char *iface;
	uid_t initial_uid;
	gid_t initial_gid;
	unsigned int max_conns_per_ip;
	size_t tmpfs_size;
	bool mount_proc;
	 LIST_HEAD(pidslist, pids_t) pids;
	 LIST_HEAD(mountptslist, mounts_t) mountpts;
};

#endif				/* _COMMON_H */
