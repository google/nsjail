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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "caps.h"
#include "config.h"
#include "logs.h"
#include "macros.h"
#include "mnt.h"
#include "user.h"
#include "util.h"

namespace cmdline {

#define _LOG_DEFAULT_FILE "/var/log/nsjail.log"

struct custom_option {
	const struct option opt;
	const char *const descr;
};

// clang-format off
static const struct custom_option custom_opts[] = {
    { { "help", no_argument, NULL, 'h' }, "Help plz.." },
    { { "mode", required_argument, NULL, 'M' },
        "Execution mode (default: 'o' [MODE_STANDALONE_ONCE]):\n"
        "  l: [MODE_LISTEN_TCP]\n\tWait for connections on a TCP port (specified with --port)\n"
        "  o: [MODE_STANDALONE_ONCE]\n\tLaunch a single process on the console using clone/execve\n"
        "  e: [MODE_STANDALONE_EXECVE]\n\tLaunch a single process on the console using execve\n"
        "  r: [MODE_STANDALONE_RERUN]\n\tLaunch a single process on the console with clone/execve, keep doing it forever" },
    { { "config", required_argument, NULL, 'C' }, "Configuration file in the config.proto ProtoBuf format (see configs/ directory for examples)" },
    { { "exec_file", required_argument, NULL, 'x' }, "File to exec (default: argv[0])" },
    { { "execute_fd", no_argument, NULL, 0x0607 }, "Use execveat() to execute a file-descriptor instead of executing the binary path. In such case argv[0]/exec_file denotes a file path before mount namespacing" },
    { { "chroot", required_argument, NULL, 'c' }, "Directory containing / of the jail (default: none)" },
    { { "no_pivotroot", no_argument, NULL, 0x600 }, "When creating a mount namespace, use mount(MS_MOVE) and chroot rather than pivot_root. Usefull when pivot_root is disallowed (e.g. initramfs). Note: escapable is some configuration" },
    { { "rw", no_argument, NULL, 0x601 }, "Mount chroot dir (/) R/W (default: R/O)" },
    { { "user", required_argument, NULL, 'u' }, "Username/uid of processes inside the jail (default: your current uid). You can also use inside_ns_uid:outside_ns_uid:count convention here. Can be specified multiple times" },
    { { "group", required_argument, NULL, 'g' }, "Groupname/gid of processes inside the jail (default: your current gid). You can also use inside_ns_gid:global_ns_gid:count convention here. Can be specified multiple times" },
    { { "hostname", required_argument, NULL, 'H' }, "UTS name (hostname) of the jail (default: 'NSJAIL')" },
    { { "cwd", required_argument, NULL, 'D' }, "Directory in the namespace the process will run (default: '/')" },
    { { "port", required_argument, NULL, 'p' }, "TCP port to bind to (enables MODE_LISTEN_TCP) (default: 0)" },
    { { "bindhost", required_argument, NULL, 0x604 }, "IP address to bind the port to (only in [MODE_LISTEN_TCP]), (default: '::')" },
    { { "max_conns", required_argument, NULL, 0x608 }, "Maximum number of connections across all IPs (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))" },
    { { "max_conns_per_ip", required_argument, NULL, 'i' }, "Maximum number of connections per one IP (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))" },
    { { "log", required_argument, NULL, 'l' }, "Log file (default: use log_fd)" },
    { { "log_fd", required_argument, NULL, 'L' }, "Log FD (default: 2)" },
    { { "time_limit", required_argument, NULL, 't' }, "Maximum time that a jail can exist, in seconds (default: 600)" },
    { { "max_cpus", required_argument, NULL, 0x508 }, "Maximum number of CPUs a single jailed process can use (default: 0 'no limit')" },
    { { "daemon", no_argument, NULL, 'd' }, "Daemonize after start" },
    { { "verbose", no_argument, NULL, 'v' }, "Verbose output" },
    { { "quiet", no_argument, NULL, 'q' }, "Log warning and more important messages only" },
    { { "really_quiet", no_argument, NULL, 'Q' }, "Log fatal messages only" },
    { { "keep_env", no_argument, NULL, 'e' }, "Pass all environment variables to the child process (default: all envars are cleared)" },
    { { "env", required_argument, NULL, 'E' }, "Additional environment variable (can be used multiple times). If the envar doesn't contain '=' (e.g. just the 'DISPLAY' string), the current envar value will be used" },
    { { "keep_caps", no_argument, NULL, 0x0501 }, "Don't drop any capabilities" },
    { { "cap", required_argument, NULL, 0x0509 }, "Retain this capability, e.g. CAP_PTRACE (can be specified multiple times)" },
    { { "silent", no_argument, NULL, 0x0502 }, "Redirect child process' fd:0/1/2 to /dev/null" },
    { { "stderr_to_null", no_argument, NULL, 0x0503 }, "Redirect child process' fd:2 (STDERR_FILENO) to /dev/null" },
    { { "skip_setsid", no_argument, NULL, 0x0504 }, "Don't call setsid(), allows for terminal signal handling in the sandboxed process. Dangerous" },
    { { "pass_fd", required_argument, NULL, 0x0505 }, "Don't close this FD before executing the child process (can be specified multiple times), by default: 0/1/2 are kept open" },
    { { "disable_no_new_privs", no_argument, NULL, 0x0507 }, "Don't set the prctl(NO_NEW_PRIVS, 1) (DANGEROUS)" },
    { { "rlimit_as", required_argument, NULL, 0x0201 }, "RLIMIT_AS in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 4096)" },
    { { "rlimit_core", required_argument, NULL, 0x0202 }, "RLIMIT_CORE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 0)" },
    { { "rlimit_cpu", required_argument, NULL, 0x0203 }, "RLIMIT_CPU, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 600)" },
    { { "rlimit_fsize", required_argument, NULL, 0x0204 }, "RLIMIT_FSIZE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 1)" },
    { { "rlimit_nofile", required_argument, NULL, 0x0205 }, "RLIMIT_NOFILE, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 32)" },
    { { "rlimit_nproc", required_argument, NULL, 0x0206 }, "RLIMIT_NPROC, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_stack", required_argument, NULL, 0x0207 }, "RLIMIT_STACK in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_memlock", required_argument, NULL, 0x0209 }, "RLIMIT_MEMLOCK in KB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_rtprio", required_argument, NULL, 0x0210 }, "RLIMIT_RTPRIO, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_msgqueue", required_argument, NULL, 0x0211 }, "RLIMIT_MSGQUEUE in bytes, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "disable_rlimits", no_argument, NULL, 0x0208 }, "Disable all rlimits, default to limits set by parent" },
    { { "persona_addr_compat_layout", no_argument, NULL, 0x0301 }, "personality(ADDR_COMPAT_LAYOUT)" },
    { { "persona_mmap_page_zero", no_argument, NULL, 0x0302 }, "personality(MMAP_PAGE_ZERO)" },
    { { "persona_read_implies_exec", no_argument, NULL, 0x0303 }, "personality(READ_IMPLIES_EXEC)" },
    { { "persona_addr_limit_3gb", no_argument, NULL, 0x0304 }, "personality(ADDR_LIMIT_3GB)" },
    { { "persona_addr_no_randomize", no_argument, NULL, 0x0305 }, "personality(ADDR_NO_RANDOMIZE)" },
    { { "disable_clone_newnet", no_argument, NULL, 'N' }, "Don't use CLONE_NEWNET. Enable global networking inside the jail" },
    { { "disable_clone_newuser", no_argument, NULL, 0x0402 }, "Don't use CLONE_NEWUSER. Requires euid==0" },
    { { "disable_clone_newns", no_argument, NULL, 0x0403 }, "Don't use CLONE_NEWNS" },
    { { "disable_clone_newpid", no_argument, NULL, 0x0404 }, "Don't use CLONE_NEWPID" },
    { { "disable_clone_newipc", no_argument, NULL, 0x0405 }, "Don't use CLONE_NEWIPC" },
    { { "disable_clone_newuts", no_argument, NULL, 0x0406 }, "Don't use CLONE_NEWUTS" },
    { { "disable_clone_newcgroup", no_argument, NULL, 0x0407 }, "Don't use CLONE_NEWCGROUP. Might be required for kernel versions < 4.6" },
    { { "enable_clone_newtime", no_argument, NULL, 0x0408 }, "Use CLONE_NEWTIME. Supported with kernel versions >= 5.3" },
    { { "uid_mapping", required_argument, NULL, 'U' }, "Add a custom uid mapping of the form inside_uid:outside_uid:count. Setting this requires newuidmap (set-uid) to be present" },
    { { "gid_mapping", required_argument, NULL, 'G' }, "Add a custom gid mapping of the form inside_gid:outside_gid:count. Setting this requires newgidmap (set-uid) to be present" },
    { { "bindmount_ro", required_argument, NULL, 'R' }, "List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "bindmount", required_argument, NULL, 'B' }, "List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "tmpfsmount", required_argument, NULL, 'T' }, "List of mountpoints to be mounted as tmpfs (R/W) inside the container. Can be specified multiple times. Supports 'dest' syntax. Alternatively, use '-m none:dest:tmpfs:size=8388608'" },
    { { "mount", required_argument, NULL, 'm' }, "Arbitrary mount, format src:dst:fs_type:options" },
    { { "symlink", required_argument, NULL, 's' }, "Symlink, format src:dst" },
    { { "disable_proc", no_argument, NULL, 0x0603 }, "Disable mounting procfs in the jail" },
    { { "proc_path", required_argument, NULL, 0x0605 }, "Path used to mount procfs (default: '/proc')" },
    { { "proc_rw", no_argument, NULL, 0x0606 }, "Is procfs mounted as R/W (default: R/O)" },
    { { "seccomp_policy", required_argument, NULL, 'P' }, "Path to file containing seccomp-bpf policy (see kafel/)" },
    { { "seccomp_string", required_argument, NULL, 0x0901 }, "String with kafel seccomp-bpf policy (see kafel/)" },
    { { "seccomp_log", no_argument, NULL, 0x0902 }, "Use SECCOMP_FILTER_FLAG_LOG. Log all actions except SECCOMP_RET_ALLOW). Supported since kernel version 4.14" },
    { { "nice_level", required_argument, NULL, 0x0903 }, "Set jailed process niceness (-20 is highest -priority, 19 is lowest). By default, set to 19" },
    { { "cgroup_mem_max", required_argument, NULL, 0x0801 }, "Maximum number of bytes to use in the group (default: '0' - disabled)" },
    { { "cgroup_mem_memsw_max", required_argument, NULL, 0x0804 }, "Maximum number of memory+swap bytes to use (default: '0' - disabled)" },
    { { "cgroup_mem_swap_max", required_argument, NULL, 0x0805 }, "Maximum number of swap bytes to use (default: '-1' - disabled)" },
    { { "cgroup_mem_mount", required_argument, NULL, 0x0802 }, "Location of memory cgroup FS (default: '/sys/fs/cgroup/memory')" },
    { { "cgroup_mem_parent", required_argument, NULL, 0x0803 }, "Which pre-existing memory cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_pids_max", required_argument, NULL, 0x0811 }, "Maximum number of pids in a cgroup (default: '0' - disabled)" },
    { { "cgroup_pids_mount", required_argument, NULL, 0x0812 }, "Location of pids cgroup FS (default: '/sys/fs/cgroup/pids')" },
    { { "cgroup_pids_parent", required_argument, NULL, 0x0813 }, "Which pre-existing pids cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_net_cls_classid", required_argument, NULL, 0x0821 }, "Class identifier of network packets in the group (default: '0' - disabled)" },
    { { "cgroup_net_cls_mount", required_argument, NULL, 0x0822 }, "Location of net_cls cgroup FS (default: '/sys/fs/cgroup/net_cls')" },
    { { "cgroup_net_cls_parent", required_argument, NULL, 0x0823 }, "Which pre-existing net_cls cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_cpu_ms_per_sec", required_argument, NULL, 0x0831 }, "Number of milliseconds of CPU time per second that the process group can use (default: '0' - no limit)" },
    { { "cgroup_cpu_mount", required_argument, NULL, 0x0832 }, "Location of cpu cgroup FS (default: '/sys/fs/cgroup/cpu')" },
    { { "cgroup_cpu_parent", required_argument, NULL, 0x0833 }, "Which pre-existing cpu cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroupv2_mount", required_argument, NULL, 0x0834}, "Location of cgroupv2 directory (default: '/sys/fs/cgroup')"},
    { { "use_cgroupv2", no_argument, NULL, 0x0835}, "Use cgroup v2"},
    { { "detect_cgroupv2", no_argument, NULL, 0x0836}, "Use cgroupv2, if it is available. (Specify instead of use_cgroupv2)"},
    { { "iface_no_lo", no_argument, NULL, 0x700 }, "Don't bring the 'lo' interface up" },
    { { "iface_own", required_argument, NULL, 0x704 }, "Move this existing network interface into the new NET namespace. Can be specified multiple times" },
    { { "macvlan_iface", required_argument, NULL, 'I' }, "Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'" },
    { { "macvlan_vs_ip", required_argument, NULL, 0x701 }, "IP of the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "macvlan_vs_nm", required_argument, NULL, 0x702 }, "Netmask of the 'vs' interface (e.g. \"255.255.255.0\")" },
    { { "macvlan_vs_gw", required_argument, NULL, 0x703 }, "Default GW for the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "macvlan_vs_ma", required_argument, NULL, 0x705 }, "MAC-address of the 'vs' interface (e.g. \"ba:ad:ba:be:45:00\")" },
    { { "macvlan_vs_mo", required_argument, NULL, 0x706 }, "Mode of the 'vs' interface. Can be either 'private', 'vepa', 'bridge' or 'passthru' (default: 'private')" },
    { { "disable_tsc", no_argument, NULL, 0x707 }, "Disable rdtsc and rdtscp instructions. WARNING: To make it effective, you also need to forbid `prctl(PR_SET_TSC, PR_TSC_ENABLE, ...)` in seccomp rules! (x86 and x86_64 only). Dynamic binaries produced by GCC seem to rely on RDTSC, but static ones should work." },
    { { "forward_signals", no_argument, NULL, 0x708 }, "Forward fatal signals to the child process instead of always using SIKGILL." },
};
// clang-format on

static const char *logYesNo(bool yes) {
	return (yes ? "true" : "false");
}

size_t GetConsoleLength(const std::string &str) {
	int result = 0;
	for (char c : str) {
		if (c == '\t') {
			result += 8;
		} else {
			++result;
		}
	}
	return result;
}

std::string FormatLine(const std::string &line, size_t max_len = 80) {
	std::string indent = line.substr(0, line.find_first_not_of(" \t"));
	size_t indent_len = GetConsoleLength(indent);
	size_t cursor = 0;
	std::string formatted;
	std::vector<std::string> words = util::strSplit(line.c_str(), ' ');
	for (const auto &word : words) {
		size_t wlen = GetConsoleLength(word);
		std::string separator = cursor == 0 ? "" : " ";
		size_t slen = GetConsoleLength(separator);
		if (cursor != 0 && cursor + slen + wlen >= max_len) {
			util::StrAppend(&formatted, "\n");
			cursor = 0;
			separator = indent;
			slen = indent_len;
		}
		util::StrAppend(&formatted, "%s%s", separator.c_str(), word.c_str());
		cursor += slen + wlen;
	}
	return formatted;
}

std::string FormatDescription(const char *descr) {
	std::string formatted;
	std::vector<std::string> lines = util::strSplit(descr, '\n');

	for (const auto &line : lines) {
		util::StrAppend(&formatted, "%s\n", FormatLine(std::string("\t") + line).c_str());
	}
	return formatted;
}

static void cmdlineOptUsage(const struct custom_option *option) {
	if (option->opt.val < 0x80) {
		LOG_HELP_BOLD(" --%s%s%c %s", option->opt.name, "|-", option->opt.val,
		    option->opt.has_arg == required_argument ? "VALUE" : "");
	} else {
		LOG_HELP_BOLD(" --%s %s", option->opt.name,
		    option->opt.has_arg == required_argument ? "VALUE" : "");
	}
	LOG_HELP("%s", FormatDescription(option->descr).c_str());
}

static void cmdlineUsage(const char *pname) {
	LOG_HELP_BOLD("Usage: %s [options] -- path_to_command [args]", pname);
	LOG_HELP_BOLD("Options:");
	for (size_t i = 0; i < ARR_SZ(custom_opts); i++) {
		cmdlineOptUsage(&custom_opts[i]);
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

void addEnv(nsjconf_t *nsjconf, const std::string &env) {
	if (env.find('=') != std::string::npos) {
		nsjconf->envs.push_back(env);
		return;
	}
	char *e = getenv(env.c_str());
	if (!e) {
		LOG_W("Requested to use the %s envar, but it's not set. It'll be ignored", QC(env));
		return;
	}
	nsjconf->envs.push_back(std::string(env).append("=").append(e));
}

void logParams(nsjconf_t *nsjconf) {
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

	LOG_I("Jail parameters: hostname:'%s', chroot:%s, process:'%s', "
	      "bind:[%s]:%d, "
	      "max_conns:%u, max_conns_per_ip:%u, time_limit:%" PRId64
	      ", personality:%#lx, daemonize:%s, clone_newnet:%s, "
	      "clone_newuser:%s, clone_newns:%s, clone_newpid:%s, clone_newipc:%s, "
	      "clone_newuts:%s, "
	      "clone_newcgroup:%s, clone_newtime:%s, keep_caps:%s, "
	      "disable_no_new_privs:%s, "
	      "max_cpus:%zu",
	    nsjconf->hostname.c_str(), QC(nsjconf->chroot),
	    nsjconf->exec_file.empty() ? nsjconf->argv[0].c_str() : nsjconf->exec_file.c_str(),
	    nsjconf->bindhost.c_str(), nsjconf->port, nsjconf->max_conns, nsjconf->max_conns_per_ip,
	    nsjconf->tlimit, nsjconf->personality, logYesNo(nsjconf->daemonize),
	    logYesNo(nsjconf->clone_newnet), logYesNo(nsjconf->clone_newuser),
	    logYesNo(nsjconf->clone_newns), logYesNo(nsjconf->clone_newpid),
	    logYesNo(nsjconf->clone_newipc), logYesNo(nsjconf->clone_newuts),
	    logYesNo(nsjconf->clone_newcgroup), logYesNo(nsjconf->clone_newtime),
	    logYesNo(nsjconf->keep_caps), logYesNo(nsjconf->disable_no_new_privs),
	    nsjconf->max_cpus);

	for (const auto &p : nsjconf->mountpts) {
		LOG_I(
		    "%s: %s", p.is_symlink ? "Symlink" : "Mount", mnt::describeMountPt(p).c_str());
	}
	for (const auto &uid : nsjconf->uids) {
		LOG_I("Uid map: inside_uid:%lu outside_uid:%lu count:%zu newuidmap:%s",
		    (unsigned long)uid.inside_id, (unsigned long)uid.outside_id, uid.count,
		    uid.is_newidmap ? "true" : "false");
		if (uid.outside_id == 0 && nsjconf->clone_newuser) {
			LOG_W("Process will be UID/EUID=0 in the global user namespace, and "
			      "will "
			      "have user root-level access to files");
		}
	}
	for (const auto &gid : nsjconf->gids) {
		LOG_I("Gid map: inside_gid:%lu outside_gid:%lu count:%zu newgidmap:%s",
		    (unsigned long)gid.inside_id, (unsigned long)gid.outside_id, gid.count,
		    gid.is_newidmap ? "true" : "false");
		if (gid.outside_id == 0 && nsjconf->clone_newuser) {
			LOG_W("Process will be GID/EGID=0 in the global user namespace, and "
			      "will "
			      "have group root-level access to files");
		}
	}
}

uint64_t parseRLimit(int res, const char *optarg, unsigned long mul) {
	if (strcasecmp(optarg, "inf") == 0) {
		return RLIM64_INFINITY;
	}
	struct rlimit64 cur;
	if (util::getrlimit(res, &cur) == -1) {
		PLOG_F("getrlimit(%d)", res);
	}
	if (strcasecmp(optarg, "def") == 0 || strcasecmp(optarg, "soft") == 0) {
		return cur.rlim_cur;
	}
	if (strcasecmp(optarg, "max") == 0 || strcasecmp(optarg, "hard") == 0) {
		return cur.rlim_max;
	}
	if (!util::isANumber(optarg)) {
		LOG_F("RLIMIT %d needs a numeric or 'max'/'hard'/'def'/'soft'/'inf' "
		      "value "
		      "('%s' "
		      "provided)",
		    res, optarg);
	}
	errno = 0;
	uint64_t val = strtoull(optarg, NULL, 0);
	if (val == ULLONG_MAX && errno != 0) {
		PLOG_F("strtoull('%s', 0)", optarg);
	}
	return val * mul;
}

static std::string argFromVec(const std::vector<std::string> &vec, size_t pos) {
	if (pos >= vec.size()) {
		return "";
	}
	return vec[pos];
}

static bool setupArgv(nsjconf_t *nsjconf, int argc, char **argv, int optind) {
	/*
	 * If user provided cmdline via nsjail [opts] -- [cmdline], then override
	 * the one from the config file
	 */
	if (optind < argc) {
		nsjconf->argv.clear();
		for (int i = optind; i < argc; i++) {
			nsjconf->argv.push_back(argv[i]);
		}
	}
	if (nsjconf->exec_file.empty() && !nsjconf->argv.empty()) {
		nsjconf->exec_file = nsjconf->argv[0];
	}
	if (nsjconf->exec_file.empty()) {
		cmdlineUsage(argv[0]);
		LOG_E("No command-line provided");
		return false;
	}

	if (nsjconf->use_execveat) {
#if !defined(__NR_execveat)
		LOG_E("Your nsjail is compiled without support for the execveat() "
		      "syscall, "
		      "yet you "
		      "specified the --execute_fd flag");
		return false;
#endif /* !defined(__NR_execveat) */
		if ((nsjconf->exec_fd = TEMP_FAILURE_RETRY(
			 open(nsjconf->exec_file.c_str(), O_RDONLY | O_PATH | O_CLOEXEC))) == -1) {
			PLOG_W("Couldn't open %s file", QC(nsjconf->exec_file));
			return false;
		}
	}
	return true;
}

static bool setupMounts(nsjconf_t *nsjconf) {
	if (!(nsjconf->chroot.empty())) {
		if (!mnt::addMountPtHead(nsjconf, nsjconf->chroot, "/", /* fstype= */ "",
			/* options= */ "",
			nsjconf->is_root_rw ? (MS_BIND | MS_REC | MS_PRIVATE)
					    : (MS_BIND | MS_REC | MS_PRIVATE | MS_RDONLY),
			/* is_dir= */ mnt::NS_DIR_YES,
			/* is_mandatory= */ true, /* src_env= */ "",
			/* dst_env= */ "", /* src_content= */ "",
			/* is_symlink= */ false)) {
			return false;
		}
	} else {
		if (!mnt::addMountPtHead(nsjconf, /* src= */ "", "/", "tmpfs",
			/* options= */ "", nsjconf->is_root_rw ? 0 : MS_RDONLY,
			/* is_dir= */ mnt::NS_DIR_YES,
			/* is_mandatory= */ true, /* src_env= */ "", /* dst_env= */ "",
			/* src_content= */ "", /* is_symlink= */ false)) {
			return false;
		}
	}
	if (!nsjconf->proc_path.empty()) {
		if (!mnt::addMountPtTail(nsjconf, /* src= */ "", nsjconf->proc_path, "proc",
			/* options= */ "", nsjconf->is_proc_rw ? 0 : MS_RDONLY,
			/* is_dir= */ mnt::NS_DIR_YES,
			/* is_mandatory= */ true, /* src_env= */ "",
			/* dst_env= */ "", /* src_content= */ "",
			/* is_symlink= */ false)) {
			return false;
		}
	}

	return true;
}

void setupUsers(nsjconf_t *nsjconf) {
	if (nsjconf->uids.empty()) {
		idmap_t uid;
		uid.inside_id = getuid();
		uid.outside_id = getuid();
		uid.count = 1U;
		uid.is_newidmap = false;
		nsjconf->uids.push_back(uid);
	}
	if (nsjconf->gids.empty()) {
		idmap_t gid;
		gid.inside_id = getgid();
		gid.outside_id = getgid();
		gid.count = 1U;
		gid.is_newidmap = false;
		nsjconf->gids.push_back(gid);
	}
}

std::string parseMACVlanMode(const char *optarg) {
	if (strcasecmp(optarg, "private") != 0 && strcasecmp(optarg, "vepa") != 0 &&
	    strcasecmp(optarg, "bridge") != 0 && strcasecmp(optarg, "passthru") != 0) {
		LOG_F("macvlan mode can only be one of the values: "
		      "'private'/'vepa'/'bridge'/'passthru' ('%s' "
		      "provided).",
		    optarg);
	}
	return std::string(optarg);
}

std::unique_ptr<nsjconf_t> parseArgs(int argc, char *argv[]) {
	std::unique_ptr<nsjconf_t> nsjconf(new nsjconf_t);

	nsjconf->use_execveat = false;
	nsjconf->exec_fd = -1;
	nsjconf->hostname = "NSJAIL";
	nsjconf->cwd = "/";
	nsjconf->port = 0;
	nsjconf->bindhost = "::";
	nsjconf->daemonize = false;
	nsjconf->tlimit = 0;
	nsjconf->max_cpus = 0;
	nsjconf->keep_env = false;
	nsjconf->keep_caps = false;
	nsjconf->disable_no_new_privs = false;
	nsjconf->rl_as = 4096ULL * (1024ULL * 1024ULL);
	nsjconf->rl_core = 0ULL;
	nsjconf->rl_cpu = 600ULL;
	nsjconf->rl_fsize = 1ULL * (1024ULL * 1024ULL);
	nsjconf->rl_nofile = 32ULL;
	nsjconf->rl_nproc = parseRLimit(RLIMIT_NPROC, "soft", 1);
	nsjconf->rl_stack = parseRLimit(RLIMIT_STACK, "soft", 1);
	nsjconf->rl_mlock = parseRLimit(RLIMIT_MEMLOCK, "soft", 1);
	nsjconf->rl_rtpr = parseRLimit(RLIMIT_RTPRIO, "soft", 1);
	nsjconf->rl_msgq = parseRLimit(RLIMIT_MSGQUEUE, "soft", 1);
	nsjconf->disable_rl = false;
	nsjconf->personality = 0;
	nsjconf->clone_newnet = true;
	nsjconf->clone_newuser = true;
	nsjconf->clone_newns = true;
	nsjconf->no_pivotroot = false;
	nsjconf->clone_newpid = true;
	nsjconf->clone_newipc = true;
	nsjconf->clone_newuts = true;
	nsjconf->clone_newcgroup = true;
	nsjconf->clone_newtime = false;
	nsjconf->mode = MODE_STANDALONE_ONCE;
	nsjconf->is_root_rw = false;
	nsjconf->is_silent = false;
	nsjconf->stderr_to_null = false;
	nsjconf->skip_setsid = false;
	nsjconf->max_conns = 0;
	nsjconf->max_conns_per_ip = 0;
	nsjconf->proc_path = "/proc";
	nsjconf->is_proc_rw = false;
	nsjconf->cgroup_mem_mount = "/sys/fs/cgroup/memory";
	nsjconf->cgroup_mem_parent = "NSJAIL";
	nsjconf->cgroup_mem_max = (size_t)0;
	nsjconf->cgroup_mem_memsw_max = (size_t)0;
	nsjconf->cgroup_mem_swap_max = (ssize_t)-1;
	nsjconf->cgroup_pids_mount = "/sys/fs/cgroup/pids";
	nsjconf->cgroup_pids_parent = "NSJAIL";
	nsjconf->cgroup_pids_max = 0U;
	nsjconf->cgroup_net_cls_mount = "/sys/fs/cgroup/net_cls";
	nsjconf->cgroup_net_cls_parent = "NSJAIL";
	nsjconf->cgroup_net_cls_classid = 0U;
	nsjconf->cgroup_cpu_mount = "/sys/fs/cgroup/cpu";
	nsjconf->cgroup_cpu_parent = "NSJAIL";
	nsjconf->cgroup_cpu_ms_per_sec = 0U;
	nsjconf->cgroupv2_mount = "/sys/fs/cgroup";
	nsjconf->use_cgroupv2 = false;
	nsjconf->detect_cgroupv2 = false;
	nsjconf->iface_lo = true;
	nsjconf->iface_vs_ip = "0.0.0.0";
	nsjconf->iface_vs_nm = "255.255.255.0";
	nsjconf->iface_vs_gw = "0.0.0.0";
	nsjconf->iface_vs_ma = "";
	nsjconf->iface_vs_mo = "private";
	nsjconf->disable_tsc = false;
	nsjconf->forward_signals = false;
	nsjconf->orig_uid = getuid();
	nsjconf->orig_euid = geteuid();
	nsjconf->seccomp_fprog.filter = NULL;
	nsjconf->seccomp_fprog.len = 0;
	nsjconf->seccomp_log = false;
	nsjconf->nice_level = 19;

	nsjconf->openfds.push_back(STDIN_FILENO);
	nsjconf->openfds.push_back(STDOUT_FILENO);
	nsjconf->openfds.push_back(STDERR_FILENO);

	/* Generate options array for getopt_long. */
	size_t options_length = ARR_SZ(custom_opts) + 1;
	struct option opts[options_length];
	for (unsigned i = 0; i < ARR_SZ(custom_opts); i++) {
		opts[i] = custom_opts[i].opt;
	}
	/* Lastly, NULL option as a terminator */
	struct option terminator = {NULL, 0, NULL, 0};
	memcpy(&opts[options_length - 1].name, &terminator, sizeof(terminator));

	int opt_index = 0;
	for (;;) {
		int c = getopt_long(argc, argv,
		    "x:H:D:C:c:p:i:u:g:l:L:t:M:NdvqQeh?E:R:B:T:m:s:P:I:U:G:", opts, &opt_index);
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
			if (!config::parseFile(nsjconf.get(), optarg)) {
				LOG_F("Couldn't parse configuration from %s file", QC(optarg));
			}
			break;
		case 'c':
			nsjconf->chroot = optarg;
			break;
		case 'p':
			if (!util::isANumber(optarg)) {
				LOG_E("Couldn't parse TCP port '%s'", optarg);
				return nullptr;
			}
			nsjconf->port = strtoumax(optarg, NULL, 0);
			nsjconf->mode = MODE_LISTEN_TCP;
			break;
		case 0x604:
			nsjconf->bindhost = optarg;
			break;
		case 0x608:
			nsjconf->max_conns = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			nsjconf->max_conns_per_ip = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			logs::logFile(optarg, STDERR_FILENO);
			break;
		case 'L':
			logs::logFile("", std::strtol(optarg, NULL, 0));
			break;
		case 'd':
			nsjconf->daemonize = true;
			break;
		case 'v':
			logs::setLogLevel(logs::DEBUG);
			break;
		case 'q':
			logs::setLogLevel(logs::WARNING);
			break;
		case 'Q':
			logs::setLogLevel(logs::FATAL);
			break;
		case 'e':
			nsjconf->keep_env = true;
			break;
		case 't':
			nsjconf->tlimit = (uint64_t)strtoull(optarg, NULL, 0);
			break;
		case 'h': /* help */
			logs::logFile("", STDOUT_FILENO);
			cmdlineUsage(argv[0]);
			exit(0);
			break;
		case 0x0201:
			nsjconf->rl_as = parseRLimit(RLIMIT_AS, optarg, (1024 * 1024));
			break;
		case 0x0202:
			nsjconf->rl_core = parseRLimit(RLIMIT_CORE, optarg, (1024 * 1024));
			break;
		case 0x0203:
			nsjconf->rl_cpu = parseRLimit(RLIMIT_CPU, optarg, 1);
			break;
		case 0x0204:
			nsjconf->rl_fsize = parseRLimit(RLIMIT_FSIZE, optarg, (1024 * 1024));
			break;
		case 0x0205:
			nsjconf->rl_nofile = parseRLimit(RLIMIT_NOFILE, optarg, 1);
			break;
		case 0x0206:
			nsjconf->rl_nproc = parseRLimit(RLIMIT_NPROC, optarg, 1);
			break;
		case 0x0207:
			nsjconf->rl_stack = parseRLimit(RLIMIT_STACK, optarg, (1024 * 1024));
			break;
		case 0x0209:
			nsjconf->rl_mlock = parseRLimit(RLIMIT_MEMLOCK, optarg, 1024);
			break;
		case 0x0210:
			nsjconf->rl_rtpr = parseRLimit(RLIMIT_RTPRIO, optarg, 1);
			break;
		case 0x0211:
			nsjconf->rl_msgq = parseRLimit(RLIMIT_MSGQUEUE, optarg, 1);
			break;
		case 0x0208:
			nsjconf->disable_rl = true;
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
			nsjconf->clone_newcgroup = false;
			break;
		case 0x0408:
			nsjconf->clone_newtime = true;
			break;
		case 0x0501:
			nsjconf->keep_caps = true;
			break;
		case 0x0502:
			nsjconf->is_silent = true;
			break;
		case 0x0503:
			nsjconf->stderr_to_null = true;
			break;
		case 0x0504:
			nsjconf->skip_setsid = true;
			break;
		case 0x0505:
			nsjconf->openfds.push_back((int)strtol(optarg, NULL, 0));
			break;
		case 0x0507:
			nsjconf->disable_no_new_privs = true;
			break;
		case 0x0508:
			nsjconf->max_cpus = strtoul(optarg, NULL, 0);
			break;
		case 0x0509: {
			int cap = caps::nameToVal(optarg);
			if (cap == -1) {
				return nullptr;
			}
			nsjconf->caps.push_back(cap);
		} break;
		case 0x0600:
			nsjconf->no_pivotroot = true;
			break;
		case 0x0601:
			nsjconf->is_root_rw = true;
			break;
		case 0x0603:
			nsjconf->proc_path.clear();
			break;
		case 0x0605:
			nsjconf->proc_path = optarg;
			break;
		case 0x0606:
			nsjconf->is_proc_rw = true;
			break;
		case 0x0607:
			nsjconf->use_execveat = true;
			break;
		case 'E':
			addEnv(nsjconf.get(), optarg);
			break;
		case 'u': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string i_id = argFromVec(subopts, 0);
			std::string o_id = argFromVec(subopts, 1);
			std::string cnt = argFromVec(subopts, 2);
			size_t count = strtoul(cnt.c_str(), nullptr, 0);
			if (!user::parseId(nsjconf.get(), i_id, o_id, count,
				/* is_gid= */ false,
				/* is_newidmap= */ false)) {
				return nullptr;
			}
		} break;
		case 'g': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string i_id = argFromVec(subopts, 0);
			std::string o_id = argFromVec(subopts, 1);
			std::string cnt = argFromVec(subopts, 2);
			size_t count = strtoul(cnt.c_str(), nullptr, 0);
			if (!user::parseId(nsjconf.get(), i_id, o_id, count,
				/* is_gid= */ true,
				/* is_newidmap= */ false)) {
				return nullptr;
			}
		} break;
		case 'U': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string i_id = argFromVec(subopts, 0);
			std::string o_id = argFromVec(subopts, 1);
			std::string cnt = argFromVec(subopts, 2);
			size_t count = strtoul(cnt.c_str(), nullptr, 0);
			if (!user::parseId(nsjconf.get(), i_id, o_id, count,
				/* is_gid= */ false,
				/* is_newidmap= */ true)) {
				return nullptr;
			}
		} break;
		case 'G': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string i_id = argFromVec(subopts, 0);
			std::string o_id = argFromVec(subopts, 1);
			std::string cnt = argFromVec(subopts, 2);
			size_t count = strtoul(cnt.c_str(), nullptr, 0);
			if (!user::parseId(nsjconf.get(), i_id, o_id, count,
				/* is_gid= */ true,
				/* is_newidmap= */ true)) {
				return nullptr;
			}
		} break;
		case 'R': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (dst.empty()) {
				dst = src;
			}
			if (!mnt::addMountPtTail(nsjconf.get(), src, dst, /* fstype= */ "",
				/* options= */ "", MS_BIND | MS_REC | MS_PRIVATE | MS_RDONLY,
				/* is_dir= */ mnt::NS_DIR_MAYBE, /* is_mandatory= */ true,
				/* src_env= */ "", /* dst_env= */ "", /* src_content= */ "",
				/* is_symlink= */ false)) {
				return nullptr;
			}
		}; break;
		case 'B': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (dst.empty()) {
				dst = src;
			}
			if (!mnt::addMountPtTail(nsjconf.get(), src, dst, /* fstype= */ "",
				/* options= */ "", MS_BIND | MS_REC | MS_PRIVATE,
				/* is_dir= */ mnt::NS_DIR_MAYBE, /* is_mandatory= */ true,
				/* src_env= */ "", /* dst_env= */ "", /* src_content= */ "",
				/* is_symlink= */ false)) {
				return nullptr;
			}
		}; break;
		case 'T': {
			if (!mnt::addMountPtTail(nsjconf.get(), "", optarg, /* fstype= */ "tmpfs",
				/* options= */ "size=4194304", 0,
				/* is_dir= */ mnt::NS_DIR_YES, /* is_mandatory= */ true,
				/* src_env= */ "", /* dst_env= */ "", /* src_content= */ "",
				/* is_symlink= */ false)) {
				return nullptr;
			}
		}; break;
		case 'm': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (dst.empty()) {
				dst = src;
			}
			std::string fs_type = argFromVec(subopts, 2);
			std::stringstream optionsStream;
			optionsStream << argFromVec(subopts, 3);
			for (std::size_t i = 4; i < subopts.size(); ++i) {
				optionsStream << ":" << subopts[i];
			}
			std::string options = optionsStream.str();
			if (!mnt::addMountPtTail(nsjconf.get(), src, dst, /* fstype= */ fs_type,
				/* options= */ options, /* flags= */ 0,
				/* is_dir= */ mnt::NS_DIR_MAYBE, /* is_mandatory= */ true,
				/* src_env= */ "", /* dst_env= */ "", /* src_content= */ "",
				/* is_symlink= */ false)) {
				return nullptr;
			}
		}; break;
		case 's': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (!mnt::addMountPtTail(nsjconf.get(), src, dst, /* fstype= */ "",
				/* options= */ "", /* flags= */ 0,
				/* is_dir= */ mnt::NS_DIR_NO, /* is_mandatory= */ true,
				/* src_env= */ "", /* dst_env= */ "", /* src_content= */ "",
				/* is_symlink= */ true)) {
				return nullptr;
			}
		}; break;
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
				return nullptr;
				break;
			}
			break;
		case 0x700:
			nsjconf->iface_lo = false;
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
		case 0x704:
			nsjconf->ifaces.push_back(optarg);
			break;
		case 0x705:
			nsjconf->iface_vs_ma = optarg;
			break;
		case 0x706:
			nsjconf->iface_vs_mo = parseMACVlanMode(optarg);
			break;
		case 0x707:
			nsjconf->disable_tsc = true;
			break;
		case 0x708:
			nsjconf->forward_signals = true;
			break;
		case 0x801:
			nsjconf->cgroup_mem_max = (size_t)strtoull(optarg, NULL, 0);
			break;
		case 0x802:
			nsjconf->cgroup_mem_mount = optarg;
			break;
		case 0x803:
			nsjconf->cgroup_mem_parent = optarg;
			break;
		case 0x804:
			nsjconf->cgroup_mem_memsw_max = (size_t)strtoull(optarg, NULL, 0);
			break;
		case 0x805:
			nsjconf->cgroup_mem_swap_max = (ssize_t)strtoll(optarg, NULL, 0);
			break;
		case 0x811:
			nsjconf->cgroup_pids_max = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 0x812:
			nsjconf->cgroup_pids_mount = optarg;
			break;
		case 0x813:
			nsjconf->cgroup_pids_parent = optarg;
			break;
		case 0x821:
			nsjconf->cgroup_net_cls_classid = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 0x822:
			nsjconf->cgroup_net_cls_mount = optarg;
			break;
		case 0x823:
			nsjconf->cgroup_net_cls_parent = optarg;
			break;
		case 0x831:
			nsjconf->cgroup_cpu_ms_per_sec = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 0x832:
			nsjconf->cgroup_cpu_mount = optarg;
			break;
		case 0x833:
			nsjconf->cgroup_cpu_parent = optarg;
			break;
		case 0x834:
			nsjconf->cgroupv2_mount = optarg;
			break;
		case 0x835:
			nsjconf->use_cgroupv2 = true;
			break;
		case 0x836:
			nsjconf->detect_cgroupv2 = true;
			break;
		case 'P':
			nsjconf->kafel_file_path = optarg;
			break;
		case 0x901:
			nsjconf->kafel_string = optarg;
			break;
		case 0x902:
			nsjconf->seccomp_log = true;
			break;
		case 0x903:
			nsjconf->nice_level = (int)strtol(optarg, NULL, 0);
			break;
		default:
			cmdlineUsage(argv[0]);
			return nullptr;
			break;
		}
	}

	if (nsjconf->daemonize && !logs::logSet()) {
		logs::logFile(_LOG_DEFAULT_FILE, STDERR_FILENO);
	}
	if (!setupMounts(nsjconf.get())) {
		return nullptr;
	}
	if (!setupArgv(nsjconf.get(), argc, argv, optind)) {
		return nullptr;
	}
	setupUsers(nsjconf.get());

	if (nsjconf->cgroup_mem_memsw_max > (size_t)0 &&
	    nsjconf->cgroup_mem_swap_max >= (ssize_t)0) {
		LOG_F("cannot set both cgroup_mem_memsw_max and cgroup_mem_swap_max");
	}

	return nsjconf;
}

}  // namespace cmdline
