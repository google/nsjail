/*

   nsjail - cmdline parsing

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

#include "cmdline.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "caps.h"
#include "config.h"
#include "log.h"
#include "mount.h"
#include "user.h"
#include "util.h"

struct custom_option {
	struct option opt;
	const char *descr;
};

/* *INDENT-OFF* */
struct custom_option custom_opts[] = {
    { { "help", no_argument, NULL, 'h' }, "Help plz.." },
    { { "mode", required_argument, NULL, 'M' },
        "Execution mode (default: o [MODE_STANDALONE_ONCE]):\n"
        "\tl: Wait for connections on a TCP port (specified with --port) "
        "[MODE_LISTEN_TCP]\n"
        "\to: Immediately launch a single process on the console using "
        "clone/execve [MODE_STANDALONE_ONCE]\n"
        "\te: Immediately launch a single process on the console using execve "
        "[MODE_STANDALONE_EXECVE]\n"
        "\tr: Immediately launch a single process on the console, keep doing it "
        "forever [MODE_STANDALONE_RERUN]" },
    { { "config", required_argument, NULL, 'C' }, "Configuration file in the config.proto ProtoBuf format" },
    { { "exec_file", required_argument, NULL, 'x' }, "File to exec (default: argv[0])" },
    { { "chroot", required_argument, NULL, 'c' }, "Directory containing / of the jail (default: none)" },
    { { "rw", no_argument, NULL, 0x601 }, "Mount / and /proc as RW (default: RO)" },
    { { "user", required_argument, NULL, 'u' }, "Username/uid of processess inside the jail (default: your current uid). You can also use inside_ns_uid:outside_ns_uid:count convention here. Can be specified multiple times" },
    { { "group", required_argument, NULL, 'g' }, "Groupname/gid of processess inside the jail (default: your current gid). You can also use inside_ns_gid:global_ns_gid:count convention here. Can be specified multiple times" },
    { { "hostname", required_argument, NULL, 'H' }, "UTS name (hostname) of the jail (default: 'NSJAIL')" },
    { { "cwd", required_argument, NULL, 'D' }, "Directory in the namespace the process will run (default: '/')" },
    { { "port", required_argument, NULL, 'p' }, "TCP port to bind to (enables MODE_LISTEN_TCP) (default: 0)" },
    { { "bindhost", required_argument, NULL, 0x604 }, "IP address to bind the port to (only in [MODE_LISTEN_TCP]), (default: '::')" },
    { { "max_conns_per_ip", required_argument, NULL, 'i' }, "Maximum number of connections per one IP (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))" },
    { { "log", required_argument, NULL, 'l' }, "Log file (default: use log_fd)" },
    { { "log_fd", required_argument, NULL, 'L' }, "Log FD (default: 2)" },
    { { "time_limit", required_argument, NULL, 't' }, "Maximum time that a jail can exist, in seconds (default: 600)" },
    { { "max_cpus", required_argument, NULL, 0x508 }, "Maximum number of CPUs a single jailed process can use (default: 0 'no limit')" },
    { { "daemon", no_argument, NULL, 'd' }, "Daemonize after start" },
    { { "verbose", no_argument, NULL, 'v' }, "Verbose output" },
    { { "quiet", no_argument, NULL, 'q' }, "Only output warning and more important messages" },
    { { "keep_env", no_argument, NULL, 'e' }, "Should all environment variables be passed to the child?" },
    { { "env", required_argument, NULL, 'E' }, "Environment variable (can be used multiple times)" },
    { { "keep_caps", no_argument, NULL, 0x0501 }, "Don't drop capabilities in the local namespace" },
    { { "silent", no_argument, NULL, 0x0502 }, "Redirect child's fd:0/1/2 to /dev/null" },
    { { "skip_setsid", no_argument, NULL, 0x0504 }, "Don't call setsid(), allows for terminal signal handling in the sandboxed process" },
    { { "pass_fd", required_argument, NULL, 0x0505 }, "Don't close this FD before executing child (can be specified multiple times), by default: 0/1/2 are kept open" },
    { { "disable_no_new_privs", no_argument, NULL, 0x0507 }, "Don't set the prctl(NO_NEW_PRIVS, 1) (DANGEROUS)" },
    { { "cap", required_argument, NULL, 0x0509 }, "Retain this capability in local namespace (e.g. CAP_PTRACE). Can be specified multiple times" },
    { { "rlimit_as", required_argument, NULL, 0x0201 }, "RLIMIT_AS in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 512)" },
    { { "rlimit_core", required_argument, NULL, 0x0202 }, "RLIMIT_CORE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 0)" },
    { { "rlimit_cpu", required_argument, NULL, 0x0203 }, "RLIMIT_CPU, 'max' for RLIM_INFINITY, 'def' for the current value (default: 600)" },
    { { "rlimit_fsize", required_argument, NULL, 0x0204 }, "RLIMIT_FSIZE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 1)" },
    { { "rlimit_nofile", required_argument, NULL, 0x0205 }, "RLIMIT_NOFILE, 'max' for RLIM_INFINITY, 'def' for the current value (default: 32)" },
    { { "rlimit_nproc", required_argument, NULL, 0x0206 }, "RLIMIT_NPROC, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')" },
    { { "rlimit_stack", required_argument, NULL, 0x0207 }, "RLIMIT_STACK in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')" },
    { { "persona_addr_compat_layout", no_argument, NULL, 0x0301 }, "personality(ADDR_COMPAT_LAYOUT)" },
    { { "persona_mmap_page_zero", no_argument, NULL, 0x0302 }, "personality(MMAP_PAGE_ZERO)" },
    { { "persona_read_implies_exec", no_argument, NULL, 0x0303 }, "personality(READ_IMPLIES_EXEC)" },
    { { "persona_addr_limit_3gb", no_argument, NULL, 0x0304 }, "personality(ADDR_LIMIT_3GB)" },
    { { "persona_addr_no_randomize", no_argument, NULL, 0x0305 }, "personality(ADDR_NO_RANDOMIZE)" },
    { { "disable_clone_newnet", no_argument, NULL, 'N' }, "Don't use CLONE_NEWNET. Enable networking inside the jail" },
    { { "disable_clone_newuser", no_argument, NULL, 0x0402 }, "Don't use CLONE_NEWUSER. Requires euid==0" },
    { { "disable_clone_newns", no_argument, NULL, 0x0403 }, "Don't use CLONE_NEWNS" },
    { { "disable_clone_newpid", no_argument, NULL, 0x0404 }, "Don't use CLONE_NEWPID" },
    { { "disable_clone_newipc", no_argument, NULL, 0x0405 }, "Don't use CLONE_NEWIPC" },
    { { "disable_clone_newuts", no_argument, NULL, 0x0406 }, "Don't use CLONE_NEWUTS" },
    { { "enable_clone_newcgroup", no_argument, NULL, 0x0407 }, "Use CLONE_NEWCGROUP" },
    { { "uid_mapping", required_argument, NULL, 'U' }, "Add a custom uid mapping of the form inside_uid:outside_uid:count. Setting this requires newuidmap to be present" },
    { { "gid_mapping", required_argument, NULL, 'G' }, "Add a custom gid mapping of the form inside_gid:outside_gid:count. Setting this requires newgidmap to be present" },
    { { "bindmount_ro", required_argument, NULL, 'R' }, "List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "bindmount", required_argument, NULL, 'B' }, "List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "tmpfsmount", required_argument, NULL, 'T' }, "List of mountpoints to be mounted as RW/tmpfs inside the container. Can be specified multiple times. Supports 'dest' syntax" },
    { { "tmpfs_size", required_argument, NULL, 0x0602 }, "Number of bytes to allocate for tmpfsmounts (default: 4194304)" },
    { { "disable_proc", no_argument, NULL, 0x0603 }, "Disable mounting /proc in the jail" },
    { { "seccomp_policy", required_argument, NULL, 'P' }, "Path to file containing seccomp-bpf policy (see kafel/)" },
    { { "seccomp_string", required_argument, NULL, 0x0901 }, "String with kafel seccomp-bpf policy (see kafel/)" },
    { { "cgroup_mem_max", required_argument, NULL, 0x0801 }, "Maximum number of bytes to use in the group (default: '0' - disabled)" },
    { { "cgroup_mem_mount", required_argument, NULL, 0x0802 }, "Location of memory cgroup FS (default: '/sys/fs/cgroup/memory')" },
    { { "cgroup_mem_parent", required_argument, NULL, 0x0803 }, "Which pre-existing memory cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_pids_max", required_argument, NULL, 0x0811 }, "Maximum number of pids in a cgroup (default: '0' - disabled)" },
    { { "cgroup_pids_mount", required_argument, NULL, 0x0812 }, "Location of pids cgroup FS (default: '/sys/fs/cgroup/pids')" },
    { { "cgroup_pids_parent", required_argument, NULL, 0x0813 }, "Which pre-existing pids cgroup to use as a parent (default: 'NSJAIL')" },
    { { "iface_no_lo", no_argument, NULL, 0x700 }, "Don't bring up the 'lo' interface" },
    { { "macvlan_iface", required_argument, NULL, 'I' }, "Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'" },
    { { "macvlan_vs_ip", required_argument, NULL, 0x701 }, "IP of the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "macvlan_vs_nm", required_argument, NULL, 0x702 }, "Netmask of the 'vs' interface (e.g. \"255.255.255.0\")" },
    { { "macvlan_vs_gw", required_argument, NULL, 0x703 }, "Default GW for the 'vs' interface (e.g. \"192.168.0.1\")" },
};

struct custom_option deprecated_opts[] = {
    // Compatibilty flags for MACVLAN.
    // TODO(rswiecki): Remove this at some point.
    { { "iface", required_argument, NULL, 'I' }, "Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'" },
    { { "iface_vs_ip", required_argument, NULL, 0x701 }, "IP of the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "iface_vs_nm", required_argument, NULL, 0x702 }, "Netmask of the 'vs' interface (e.g. \"255.255.255.0\")" },
    { { "iface_vs_gw", required_argument, NULL, 0x703 }, "Default GW for the 'vs' interface (e.g. \"192.168.0.1\")" },
};
/*  *INDENT-ON* */

static const char *logYesNo(bool yes)
{
	return (yes ? "true" : "false");
}

static void cmdlineOptUsage(struct custom_option *option)
{
	if (option->opt.val < 0x80) {
		LOG_HELP_BOLD(" --%s%s%c %s", option->opt.name, "|-", option->opt.val,
			      option->opt.has_arg == required_argument ? "VALUE" : "");
	} else {
		LOG_HELP_BOLD(" --%s %s", option->opt.name,
			      option->opt.has_arg == required_argument ? "VALUE" : "");
	}
	LOG_HELP("\t%s", option->descr);
}

static void cmdlineUsage(const char *pname)
{
	LOG_HELP_BOLD("Usage: %s [options] -- path_to_command [args]", pname);
	LOG_HELP_BOLD("Options:");
	for (size_t i = 0; i < ARRAYSIZE(custom_opts); i++) {
		cmdlineOptUsage(&custom_opts[i]);
	}
	LOG_HELP_BOLD("\nDeprecated options:");
	for (size_t i = 0; i < ARRAYSIZE(deprecated_opts); i++) {
		cmdlineOptUsage(&deprecated_opts[i]);
		// Find replacement flag.
		for (size_t j = 0; j < ARRAYSIZE(custom_opts); j++) {
			if (custom_opts[j].opt.val == deprecated_opts[i].opt.val) {
				LOG_HELP_BOLD("\tDEPRECATED: Use %s instead.",
					      custom_opts[j].opt.name);
				break;
			}
		}
	}
	LOG_HELP_BOLD("\n Examples: ");
	LOG_HELP(" Wait on a port 31337 for connections, and run /bin/sh");
	LOG_HELP_BOLD("  nsjail -Ml --port 31337 --chroot / -- /bin/sh -i");
	LOG_HELP(" Re-run echo command as a sub-process");
	LOG_HELP_BOLD("  nsjail -Mr --chroot / -- /bin/echo \"ABC\"");
	LOG_HELP(" Run echo command once only, as a sub-process");
	LOG_HELP_BOLD("  nsjail -Mo --chroot / -- /bin/echo \"ABC\"");
	LOG_HELP(" Execute echo command directly, without a supervising process");
	LOG_HELP_BOLD("  nsjail -Me --chroot / --disable_proc -- /bin/echo \"ABC\"");
}

void cmdlineLogParams(struct nsjconf_t *nsjconf)
{
	switch (nsjconf->mode) {
	case MODE_LISTEN_TCP:
		LOG_I("Mode: LISTEN_TCP");
		break;
	case MODE_STANDALONE_ONCE:
		LOG_I("Mode: STANDALONE_ONCE");
		break;
	case MODE_STANDALONE_EXECVE:
		LOG_I("Mode: STANDALONE_EXECVE");
		break;
	case MODE_STANDALONE_RERUN:
		LOG_I("Mode: STANDALONE_RERUN");
		break;
	default:
		LOG_F("Mode: UNKNOWN");
		break;
	}

	LOG_I("Jail parameters: hostname:'%s', chroot:'%s', process:'%s', "
	      "bind:[%s]:%d, "
	      "max_conns_per_ip:%u, time_limit:%ld, personality:%#lx, daemonize:%s, "
	      "clone_newnet:%s, clone_newuser:%s, clone_newns:%s, clone_newpid:%s, "
	      "clone_newipc:%s, clonew_newuts:%s, clone_newcgroup:%s, keep_caps:%s, "
	      "tmpfs_size:%zu, disable_no_new_privs:%s, max_cpus:%zu",
	      nsjconf->hostname, nsjconf->chroot ? nsjconf->chroot : "[NULL]", nsjconf->argv[0],
	      nsjconf->bindhost, nsjconf->port, nsjconf->max_conns_per_ip, nsjconf->tlimit,
	      nsjconf->personality, logYesNo(nsjconf->daemonize), logYesNo(nsjconf->clone_newnet),
	      logYesNo(nsjconf->clone_newuser), logYesNo(nsjconf->clone_newns),
	      logYesNo(nsjconf->clone_newpid), logYesNo(nsjconf->clone_newipc),
	      logYesNo(nsjconf->clone_newuts), logYesNo(nsjconf->clone_newcgroup),
	      logYesNo(nsjconf->keep_caps), nsjconf->tmpfs_size,
	      logYesNo(nsjconf->disable_no_new_privs), nsjconf->max_cpus);

	{
		struct mounts_t *p;
		TAILQ_FOREACH(p, &nsjconf->mountpts, pointers) {
			LOG_I("%s: %s", p->isSymlink ? "Symlink" : "Mount point",
			      mountDescribeMountPt(p));
		}
	}
	{
		struct idmap_t *p;
		TAILQ_FOREACH(p, &nsjconf->uids, pointers) {
			LOG_I("Uid map: inside_uid:%lu outside_uid:%lu count:%zu newuidmap:%s",
			      (unsigned long)p->inside_id, (unsigned long)p->outside_id, p->count,
			      p->is_newidmap ? "true" : "false");
			if (p->outside_id == 0) {
				LOG_W
				    ("Process will be UID/EUID=0 in the global user namespace, and will have user root-level access to files");
			}
		}
		TAILQ_FOREACH(p, &nsjconf->gids, pointers) {
			LOG_I("Gid map: inside_gid:%lu outside_gid:%lu count:%zu newgidmap:%s",
			      (unsigned long)p->inside_id, (unsigned long)p->outside_id, p->count,
			      p->is_newidmap ? "true" : "false");
			if (p->outside_id == 0) {
				LOG_W
				    ("Process will be GID/EGID=0 in the global user namespace, and will have group root-level access to files");
			}
		}
	}
}

__rlim64_t cmdlineParseRLimit(int res, const char *optarg, unsigned long mul)
{
	struct rlimit64 cur;
	if (prlimit64(0, res, NULL, &cur) == -1) {
		PLOG_F("getrlimit(%d)", res);
	}
	if (strcasecmp(optarg, "max") == 0) {
		return cur.rlim_max;
	}
	if (strcasecmp(optarg, "def") == 0) {
		return cur.rlim_cur;
	}
	if (utilIsANumber(optarg) == false) {
		LOG_F("RLIMIT %d needs a numeric or 'max'/'def' value ('%s' provided)", res,
		      optarg);
	}
	__rlim64_t val = strtoull(optarg, NULL, 0) * mul;
	if (val == ULLONG_MAX && errno != 0) {
		PLOG_F("strtoul('%s', 0)", optarg);
	}
	return val;
}

/* findSpecDestination mutates spec (source:dest) to have a null byte instead
 * of ':' in between source and dest, then returns a pointer to the dest
 * string. */
static char *cmdlineSplitStrByColon(char *spec)
{
	if (spec == NULL) {
		return NULL;
	}

	char *dest = spec;
	while (*dest != ':' && *dest != '\0') {
		dest++;
	}

	switch (*dest) {
	case ':':
		*dest = '\0';
		return dest + 1;
	case '\0':
		return NULL;
	default:
		LOG_F("Impossible condition in cmdlineSplitStrByColon()");
		return NULL;
	}
}

bool cmdlineParse(int argc, char *argv[], struct nsjconf_t * nsjconf)
{
    /*  *INDENT-OFF* */
    (*nsjconf) = (const struct nsjconf_t){
        .exec_file = NULL,
        .hostname = "NSJAIL",
        .cwd = "/",
        .chroot = NULL,
        .argv = NULL,
        .port = 0,
        .bindhost = "::",
        .log_fd = STDERR_FILENO,
        .logfile = NULL,
        .loglevel = INFO,
        .daemonize = false,
        .tlimit = 0,
        .max_cpus = 0,
        .keep_caps = false,
        .disable_no_new_privs = false,
        .rl_as = 512 * (1024 * 1024),
        .rl_core = 0,
        .rl_cpu = 600,
        .rl_fsize = 1 * (1024 * 1024),
        .rl_nofile = 32,
        .rl_nproc = cmdlineParseRLimit(RLIMIT_NPROC, "def", 1),
        .rl_stack = cmdlineParseRLimit(RLIMIT_STACK, "def", 1),
        .personality = 0,
        .clone_newnet = true,
        .clone_newuser = true,
        .clone_newns = true,
        .clone_newpid = true,
        .clone_newipc = true,
        .clone_newuts = true,
        .clone_newcgroup = false,
        .mode = MODE_STANDALONE_ONCE,
        .is_root_rw = false,
        .is_silent = false,
        .skip_setsid = false,
        .max_conns_per_ip = 0,
        .tmpfs_size = 4 * (1024 * 1024),
        .mount_proc = true,
        .cgroup_mem_mount = "/sys/fs/cgroup/memory",
        .cgroup_mem_parent = "NSJAIL",
        .cgroup_mem_max = (size_t)0,
        .cgroup_pids_mount = "/sys/fs/cgroup/pids",
        .cgroup_pids_parent = "NSJAIL",
        .cgroup_pids_max = (size_t)0,
        .iface_no_lo = false,
        .iface_vs = NULL,
        .iface_vs_ip = "0.0.0.0",
        .iface_vs_nm = "255.255.255.0",
        .iface_vs_gw = "0.0.0.0",
        .kafel_file = NULL,
        .kafel_string = NULL,
        .num_cpus = sysconf(_SC_NPROCESSORS_ONLN),
    };
    /*  *INDENT-ON* */

	TAILQ_INIT(&nsjconf->pids);
	TAILQ_INIT(&nsjconf->mountpts);
	TAILQ_INIT(&nsjconf->open_fds);
	TAILQ_INIT(&nsjconf->envs);
	TAILQ_INIT(&nsjconf->uids);
	TAILQ_INIT(&nsjconf->gids);
	TAILQ_INIT(&nsjconf->caps);

	static char cmdlineTmpfsSz[PATH_MAX] = "size=4194304";

	struct ints_t *f;
	f = utilMalloc(sizeof(struct ints_t));
	f->val = STDIN_FILENO;
	TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);
	f = utilMalloc(sizeof(struct ints_t));
	f->val = STDOUT_FILENO;
	TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);
	f = utilMalloc(sizeof(struct ints_t));
	f->val = STDERR_FILENO;
	TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);

	// Generate options array for getopt_long.
	size_t options_length = ARRAYSIZE(custom_opts) + ARRAYSIZE(deprecated_opts) + 1;
	struct option opts[options_length];
	for (unsigned i = 0; i < ARRAYSIZE(custom_opts); i++) {
		opts[i] = custom_opts[i].opt;
	}
	for (unsigned i = 0; i < ARRAYSIZE(deprecated_opts); i++) {
		opts[ARRAYSIZE(custom_opts) + i] = deprecated_opts[i].opt;
	}
	// Last, NULL option as a terminator.
	struct option terminator = { NULL, 0, NULL, 0 };
	memcpy(&opts[options_length - 1].name, &terminator, sizeof(terminator));

	int opt_index = 0;
	for (;;) {
		int c = getopt_long(argc, argv,
				    "x:H:D:C:c:p:i:u:g:l:L:t:M:Ndvqeh?E:R:B:T:P:I:U:G:", opts,
				    &opt_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'x':
			nsjconf->exec_file = optarg;
			break;
		case 'H':
			nsjconf->hostname = optarg;
			break;
		case 'D':
			nsjconf->cwd = optarg;
			break;
		case 'C':
			if (configParse(nsjconf, optarg) == false) {
				LOG_F("Couldn't parse configuration from '%s' file", optarg);
			}
			break;
		case 'c':
			nsjconf->chroot = optarg;
			break;
		case 'p':
			nsjconf->port = strtoul(optarg, NULL, 0);
			nsjconf->mode = MODE_LISTEN_TCP;
			break;
		case 0x604:
			nsjconf->bindhost = optarg;
			break;
		case 'i':
			nsjconf->max_conns_per_ip = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			nsjconf->logfile = optarg;
			if (logInitLogFile(nsjconf) == false) {
				return false;
			}
			break;
		case 'L':
			nsjconf->log_fd = strtol(optarg, NULL, 0);
			if (logInitLogFile(nsjconf) == false) {
				return false;
			}
			break;
		case 'd':
			nsjconf->daemonize = true;
			break;
		case 'v':
			nsjconf->loglevel = DEBUG;
			if (logInitLogFile(nsjconf) == false) {
				return false;
			}
			break;
		case 'q':
			nsjconf->loglevel = WARNING;
			if (logInitLogFile(nsjconf) == false) {
				return false;
			}
			break;
		case 'e':
			nsjconf->keep_env = true;
			break;
		case 't':
			nsjconf->tlimit = strtol(optarg, NULL, 0);
			break;
		case 'h':	/* help */
			cmdlineUsage(argv[0]);
			exit(0);
			break;
		case 0x0201:
			nsjconf->rl_as = cmdlineParseRLimit(RLIMIT_AS, optarg, (1024 * 1024));
			break;
		case 0x0202:
			nsjconf->rl_core = cmdlineParseRLimit(RLIMIT_CORE, optarg, (1024 * 1024));
			break;
		case 0x0203:
			nsjconf->rl_cpu = cmdlineParseRLimit(RLIMIT_CPU, optarg, 1);
			break;
		case 0x0204:
			nsjconf->rl_fsize = cmdlineParseRLimit(RLIMIT_FSIZE, optarg, (1024 * 1024));
			break;
		case 0x0205:
			nsjconf->rl_nofile = cmdlineParseRLimit(RLIMIT_NOFILE, optarg, 1);
			break;
		case 0x0206:
			nsjconf->rl_nproc = cmdlineParseRLimit(RLIMIT_NPROC, optarg, 1);
			break;
		case 0x0207:
			nsjconf->rl_stack = cmdlineParseRLimit(RLIMIT_STACK, optarg, (1024 * 1024));
			break;
		case 0x0301:
			nsjconf->personality |= ADDR_COMPAT_LAYOUT;
			break;
		case 0x0302:
			nsjconf->personality |= MMAP_PAGE_ZERO;
			break;
		case 0x0303:
			nsjconf->personality |= READ_IMPLIES_EXEC;
			break;
		case 0x0304:
			nsjconf->personality |= ADDR_LIMIT_3GB;
			break;
		case 0x0305:
			nsjconf->personality |= ADDR_NO_RANDOMIZE;
			break;
		case 'N':
			nsjconf->clone_newnet = false;
			break;
		case 0x0402:
			nsjconf->clone_newuser = false;
			break;
		case 0x0403:
			nsjconf->clone_newns = false;
			break;
		case 0x0404:
			nsjconf->clone_newpid = false;
			break;
		case 0x0405:
			nsjconf->clone_newipc = false;
			break;
		case 0x0406:
			nsjconf->clone_newuts = false;
			break;
		case 0x0407:
			nsjconf->clone_newcgroup = true;
			break;
		case 0x0501:
			nsjconf->keep_caps = true;
			break;
		case 0x0502:
			nsjconf->is_silent = true;
			break;
		case 0x0504:
			nsjconf->skip_setsid = true;
			break;
		case 0x0505:{
				struct ints_t *f;
				f = utilMalloc(sizeof(struct ints_t));
				f->val = (int)strtol(optarg, NULL, 0);
				TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);
			} break;
		case 0x0507:
			nsjconf->disable_no_new_privs = true;
			break;
		case 0x0508:
			nsjconf->max_cpus = strtoul(optarg, NULL, 0);
			break;
		case 0x509:{
				struct ints_t *f = utilMalloc(sizeof(struct ints_t));
				f->val = capsNameToVal(optarg);
				if (f->val == -1) {
					return false;
				}
				TAILQ_INSERT_HEAD(&nsjconf->caps, f, pointers);
			}
			break;
		case 0x0601:
			nsjconf->is_root_rw = true;
			break;
		case 0x0602:
			nsjconf->tmpfs_size = strtoull(optarg, NULL, 0);
			snprintf(cmdlineTmpfsSz, sizeof(cmdlineTmpfsSz), "size=%zu",
				 nsjconf->tmpfs_size);
			break;
		case 0x0603:
			nsjconf->mount_proc = false;
			break;
		case 'E':{
				struct charptr_t *p = utilMalloc(sizeof(struct charptr_t));
				p->val = optarg;
				TAILQ_INSERT_TAIL(&nsjconf->envs, p, pointers);
			} break;
		case 'u':{
				char *i_id = optarg;
				char *o_id = cmdlineSplitStrByColon(i_id);
				char *cnt = cmdlineSplitStrByColon(o_id);
				size_t count = (cnt == NULL || strlen(cnt) == 0)
				    ? 1U : (size_t) strtoull(cnt,
							     NULL,
							     0);
				if (userParseId(nsjconf, i_id, o_id, count, false /* is_gid */ ,
						false /* is_newidmap */ )
				    == false) {
					return false;
				}
			}
			break;
		case 'g':{
				char *i_id = optarg;
				char *o_id = cmdlineSplitStrByColon(i_id);
				char *cnt = cmdlineSplitStrByColon(o_id);
				size_t count = (cnt == NULL || strlen(cnt) == 0)
				    ? 1U : (size_t) strtoull(cnt,
							     NULL,
							     0);
				if (userParseId(nsjconf, i_id, o_id, count, true /* is_gid */ ,
						false /* is_newidmap */ )
				    == false) {
					return false;
				}
			}
			break;
		case 'U':{
				char *i_id = optarg;
				char *o_id = cmdlineSplitStrByColon(i_id);
				char *cnt = cmdlineSplitStrByColon(o_id);
				size_t count = (cnt == NULL || strlen(cnt) == 0)
				    ? 1U : (size_t) strtoull(cnt,
							     NULL,
							     0);
				if (userParseId(nsjconf, i_id, o_id, count, false /* is_gid */ ,
						true /* is_newidmap */ )
				    == false) {
					return false;
				}
			}
			break;
		case 'G':{
				char *i_id = optarg;
				char *o_id = cmdlineSplitStrByColon(i_id);
				char *cnt = cmdlineSplitStrByColon(o_id);
				size_t count = (cnt == NULL || strlen(cnt) == 0)
				    ? 1U : (size_t) strtoull(cnt,
							     NULL,
							     0);
				if (userParseId(nsjconf, i_id, o_id, count, true /* is_gid */ ,
						true /* is_newidmap */ )
				    == false) {
					return false;
				}
			}
			break;
		case 'R':{
				struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
				p->src = optarg;
				p->src_content = NULL;
				p->src_content_len = 0;
				const char *dst = cmdlineSplitStrByColon(optarg);
				p->dst = dst ? dst : optarg;
				p->flags = MS_BIND | MS_REC | MS_RDONLY;
				p->options = "";
				p->fs_type = "";
				p->isDir = mountIsDir(optarg);
				p->isSymlink = false;
				p->mandatory = true;
				TAILQ_INSERT_TAIL(&nsjconf->mountpts, p, pointers);
			} break;
		case 'B':{
				struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
				p->src = optarg;
				p->src_content = NULL;
				p->src_content_len = 0;
				const char *dst = cmdlineSplitStrByColon(optarg);
				p->dst = dst ? dst : optarg;
				p->flags = MS_BIND | MS_REC;
				p->options = "";
				p->fs_type = "";
				p->isDir = mountIsDir(optarg);
				p->isSymlink = false;
				p->mandatory = true;
				TAILQ_INSERT_TAIL(&nsjconf->mountpts, p, pointers);
			} break;
		case 'T':{
				struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
				p->src = NULL;
				p->src_content = NULL;
				p->src_content_len = 0;
				p->dst = optarg;
				p->flags = 0;
				p->options = cmdlineTmpfsSz;
				p->fs_type = "tmpfs";
				p->isDir = true;
				p->isSymlink = false;
				p->mandatory = true;
				TAILQ_INSERT_TAIL(&nsjconf->mountpts, p, pointers);
			} break;
		case 'M':
			switch (optarg[0]) {
			case 'l':
				nsjconf->mode = MODE_LISTEN_TCP;
				break;
			case 'o':
				nsjconf->mode = MODE_STANDALONE_ONCE;
				break;
			case 'e':
				nsjconf->mode = MODE_STANDALONE_EXECVE;
				break;
			case 'r':
				nsjconf->mode = MODE_STANDALONE_RERUN;
				break;
			default:
				LOG_E("Modes supported: -M l - MODE_LISTEN_TCP (default)");
				LOG_E("                 -M o - MODE_STANDALONE_ONCE");
				LOG_E("                 -M r - MODE_STANDALONE_RERUN");
				LOG_E("                 -M e - MODE_STANDALONE_EXECVE");
				cmdlineUsage(argv[0]);
				return false;
				break;
			}
			break;
		case 0x700:
			nsjconf->iface_no_lo = true;
			break;
		case 'I':
			nsjconf->iface_vs = optarg;
			break;
		case 0x701:
			nsjconf->iface_vs_ip = optarg;
			break;
		case 0x702:
			nsjconf->iface_vs_nm = optarg;
			break;
		case 0x703:
			nsjconf->iface_vs_gw = optarg;
			break;
		case 0x801:
			nsjconf->cgroup_mem_max = (size_t) strtoull(optarg, NULL, 0);
			break;
		case 0x802:
			nsjconf->cgroup_mem_mount = optarg;
			break;
		case 0x803:
			nsjconf->cgroup_mem_parent = optarg;
			break;
		case 0x811:
			nsjconf->cgroup_pids_max = (size_t) strtoull(optarg, NULL, 0);
			break;
		case 0x812:
			nsjconf->cgroup_pids_mount = optarg;
			break;
		case 0x813:
			nsjconf->cgroup_pids_parent = optarg;
			break;
		case 'P':
			if ((nsjconf->kafel_file = fopen(optarg, "r")) == NULL) {
				PLOG_F("Couldn't open '%s'", optarg);
			}
			break;
		case 0x0901:
			nsjconf->kafel_string = optarg;
			break;
		default:
			cmdlineUsage(argv[0]);
			return false;
			break;
		}
	}

	if (nsjconf->mount_proc == true) {
		struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
		p->src = NULL;
		p->src_content = NULL;
		p->src_content_len = 0;
		p->dst = "/proc";
		p->flags = 0;
		if (nsjconf->is_root_rw == false) {
			p->flags |= MS_RDONLY;
		}
		p->options = "";
		p->fs_type = "proc";
		p->isDir = true;
		p->isSymlink = false;
		p->mandatory = true;
		TAILQ_INSERT_HEAD(&nsjconf->mountpts, p, pointers);
	}
	if (nsjconf->chroot != NULL) {
		struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
		p->src = nsjconf->chroot;
		p->src_content = NULL;
		p->src_content_len = 0;
		p->dst = "/";
		p->flags = MS_BIND | MS_REC;
		if (nsjconf->is_root_rw == false) {
			p->flags |= MS_RDONLY;
		}
		p->options = "";
		p->fs_type = "";
		p->isDir = true;
		p->isSymlink = false;
		p->mandatory = true;
		TAILQ_INSERT_HEAD(&nsjconf->mountpts, p, pointers);
	} else {
		struct mounts_t *p = utilMalloc(sizeof(struct mounts_t));
		p->src = NULL;
		p->src_content = NULL;
		p->src_content_len = 0;
		p->dst = "/";
		p->flags = 0;
		if (nsjconf->is_root_rw == false) {
			p->flags |= MS_RDONLY;
		}
		p->options = "";
		p->fs_type = "tmpfs";
		p->isDir = true;
		p->isSymlink = false;
		p->mandatory = true;
		TAILQ_INSERT_HEAD(&nsjconf->mountpts, p, pointers);
	}

	if (TAILQ_EMPTY(&nsjconf->uids)) {
		struct idmap_t *p = utilMalloc(sizeof(struct idmap_t));
		p->inside_id = getuid();
		p->outside_id = getuid();
		p->count = 1U;
		p->is_newidmap = false;
		TAILQ_INSERT_HEAD(&nsjconf->uids, p, pointers);
	}
	if (TAILQ_EMPTY(&nsjconf->gids)) {
		struct idmap_t *p = utilMalloc(sizeof(struct idmap_t));
		p->inside_id = getgid();
		p->outside_id = getgid();
		p->count = 1U;
		p->is_newidmap = false;
		TAILQ_INSERT_HEAD(&nsjconf->gids, p, pointers);
	}

	if (logInitLogFile(nsjconf) == false) {
		return false;
	}

	if (argv[optind]) {
		nsjconf->argv = &argv[optind];
	}
	if (nsjconf->argv == NULL || nsjconf->argv[0] == NULL) {
		LOG_E("No command provided");
		cmdlineUsage(argv[0]);
		return false;
	}
	if (nsjconf->exec_file == NULL) {
		nsjconf->exec_file = nsjconf->argv[0];
	}

	return true;
}
