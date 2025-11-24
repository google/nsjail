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

#include <linux/filter.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "config.pb.h"

static const int nssigs[] = {
    SIGINT,
    SIGQUIT,
    SIGUSR1,
    SIGALRM,
    SIGCHLD,
    SIGTERM,
    SIGTTIN,
    SIGTTOU,
    SIGPIPE,
};

struct pids_t {
	time_t start;
	std::string remote_txt;
	struct sockaddr_in6 remote_addr;
	int pid_syscall_fd;
	pid_t pasta_pid;
};

struct idmap_t {
	uid_t inside_id;
	uid_t outside_id;
	size_t count;
	bool is_newidmap;
};

enum ns_mode_t {
	MODE_LISTEN_TCP = 0,
	MODE_STANDALONE_ONCE,
	MODE_STANDALONE_EXECVE,
	MODE_STANDALONE_RERUN
};

struct pipemap_t {
	int sock_fd;
	int pipe_in;
	int pipe_out;
	pid_t pid;
	bool operator==(const pipemap_t& o) {
		return sock_fd == o.sock_fd && pipe_in == o.pipe_in && pipe_out == o.pipe_out;
	}
};

struct nsj_t {
	nsjail::NsJailConfig njc;

	int exec_fd;
	std::vector<std::string> argv;
	uid_t orig_uid;
	uid_t orig_euid;
	std::map<pid_t, pids_t> pids;
	std::vector<idmap_t> uids;
	std::vector<idmap_t> gids;
	std::vector<int> openfds;

	std::vector<pipemap_t> pipes;
	std::string chroot;
	std::string proc_path;
	bool is_root_rw;
	bool is_proc_rw;
	struct sock_fprog seccomp_fprog;
};

#endif /* _NSJAIL_H */
