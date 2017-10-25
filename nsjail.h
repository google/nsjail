/*

   nsjail
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.
   Copyright 2016 Sergiusz Bazanski. All Rights Reserved.

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

#ifndef NS_NSJAIL_H
#define NS_NSJAIL_H

#include <netinet/ip6.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/queue.h>
#include <time.h>

static const int nssigs[] = {
    SIGINT,
    SIGQUIT,
    SIGUSR1,
    SIGALRM,
    SIGCHLD,
    SIGTERM,
};

struct pids_t {
	pid_t pid;
	time_t start;
	char remote_txt[64];
	struct sockaddr_in6 remote_addr;
	int pid_syscall_fd;
	TAILQ_ENTRY(pids_t)
	pointers;
};

struct mounts_t {
	const char* src;
	const uint8_t* src_content;
	size_t src_content_len;
	const char* dst;
	const char* fs_type;
	const char* options;
	uintptr_t flags;
	bool isDir;
	bool isSymlink;
	bool mandatory;
	bool mounted;
	TAILQ_ENTRY(mounts_t)
	pointers;
};

struct idmap_t {
	uid_t inside_id;
	uid_t outside_id;
	size_t count;
	bool is_newidmap;
	TAILQ_ENTRY(idmap_t)
	pointers;
};

struct ints_t {
	int val;
	TAILQ_ENTRY(ints_t)
	pointers;
};

enum ns_mode_t {
	MODE_LISTEN_TCP = 0,
	MODE_STANDALONE_ONCE,
	MODE_STANDALONE_EXECVE,
	MODE_STANDALONE_RERUN
};

struct charptr_t {
	const char* val;
	TAILQ_ENTRY(charptr_t)
	pointers;
};

enum llevel_t {
	DEBUG = 0,
	INFO,
	WARNING,
	ERROR,
	FATAL,
	HELP,
	HELP_BOLD,
};

struct nsjconf_t {
	const char* exec_file;
	bool use_execveat;
	int exec_fd;
	const char** argv;
	const char* hostname;
	const char* cwd;
	const char* chroot;
	int port;
	const char* bindhost;
	int log_fd;
	const char* logfile;
	enum llevel_t loglevel;
	bool daemonize;
	time_t tlimit;
	size_t max_cpus;
	bool keep_env;
	bool keep_caps;
	bool disable_no_new_privs;
	uint64_t rl_as;
	uint64_t rl_core;
	uint64_t rl_cpu;
	uint64_t rl_fsize;
	uint64_t rl_nofile;
	uint64_t rl_nproc;
	uint64_t rl_stack;
	unsigned long personality;
	bool clone_newnet;
	bool clone_newuser;
	bool clone_newns;
	bool clone_newpid;
	bool clone_newipc;
	bool clone_newuts;
	bool clone_newcgroup;
	enum ns_mode_t mode;
	bool is_root_rw;
	bool is_silent;
	bool skip_setsid;
	unsigned int max_conns_per_ip;
	size_t tmpfs_size;
	bool mount_proc;
	const char* proc_path;
	bool is_proc_rw;
	bool iface_no_lo;
	const char* iface_vs;
	const char* iface_vs_ip;
	const char* iface_vs_nm;
	const char* iface_vs_gw;
	const char* cgroup_mem_mount;
	const char* cgroup_mem_parent;
	size_t cgroup_mem_max;
	const char* cgroup_pids_mount;
	const char* cgroup_pids_parent;
	unsigned int cgroup_pids_max;
	const char* cgroup_net_cls_mount;
	const char* cgroup_net_cls_parent;
	unsigned int cgroup_net_cls_classid;
	FILE* kafel_file;
	char* kafel_string;
	long num_cpus;
	uid_t orig_uid;
	TAILQ_HEAD(udmaplist, idmap_t)
	uids;
	TAILQ_HEAD(gdmaplist, idmap_t)
	gids;
	TAILQ_HEAD(envlist, charptr_t)
	envs;
	TAILQ_HEAD(pidslist, pids_t)
	pids;
	TAILQ_HEAD(mountptslist, mounts_t)
	mountpts;
	TAILQ_HEAD(fdslistt, ints_t)
	open_fds;
	TAILQ_HEAD(capslistt, ints_t)
	caps;
};

#endif /* _NSJAIL_H */
