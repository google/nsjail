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
	const char* const descr;
};

// clang-format off
static const struct custom_option custom_opts[] = {
    { { "help", no_argument, nullptr, 'h' }, "Help plz.." },
    { { "mode", required_argument, nullptr, 'M' },
        "Execution mode (default: 'o' [MODE_STANDALONE_ONCE]):\n"
        "  l: [MODE_LISTEN_TCP]\n\tWait for connections on a TCP port (specified with --port)\n"
        "  o: [MODE_STANDALONE_ONCE]\n\tLaunch a single process on the console using clone/execve\n"
        "  e: [MODE_STANDALONE_EXECVE]\n\tLaunch a single process on the console using execve\n"
        "  r: [MODE_STANDALONE_RERUN]\n\tLaunch a single process on the console with clone/execve, keep doing it forever" },
    { { "config", required_argument, nullptr, 'C' }, "Configuration file in the config.proto ProtoBuf format (see configs/ directory for examples)" },
    { { "exec_file", required_argument, nullptr, 'x' }, "File to exec (default: argv[0])" },
    { { "execute_fd", no_argument, nullptr, 0x0607 }, "Use execveat() to execute a file-descriptor instead of executing the binary path. In such case argv[0]/exec_file denotes a file path before mount namespacing" },
    { { "chroot", required_argument, nullptr, 'c' }, "Directory containing / of the jail (default: none)" },
    { { "no_pivotroot", no_argument, nullptr, 0x600 }, "When creating a mount namespace, use mount(MS_MOVE) and chroot rather than pivot_root. Usefull when pivot_root is disallowed (e.g. initramfs). Note: escapable is some configuration" },
    { { "rw", no_argument, nullptr, 0x601 }, "Mount chroot dir (/) R/W (default: R/O)" },
    { { "user", required_argument, nullptr, 'u' }, "Username/uid of processes inside the jail (default: your current uid). You can also use inside_ns_uid:outside_ns_uid:count convention here. Can be specified multiple times" },
    { { "group", required_argument, nullptr, 'g' }, "Groupname/gid of processes inside the jail (default: your current gid). You can also use inside_ns_gid:global_ns_gid:count convention here. Can be specified multiple times" },
    { { "hostname", required_argument, nullptr, 'H' }, "UTS name (hostname) of the jail (default: 'NSJAIL')" },
    { { "cwd", required_argument, nullptr, 'D' }, "Directory in the namespace the process will run (default: '/')" },
    { { "port", required_argument, nullptr, 'p' }, "TCP port to bind to (enables MODE_LISTEN_TCP) (default: 0)" },
    { { "bindhost", required_argument, nullptr, 0x604 }, "IP address to bind the port to (only in [MODE_LISTEN_TCP]), (default: '::')" },
    { { "max_conns", required_argument, nullptr, 0x608 }, "Maximum number of connections across all IPs (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))" },
    { { "max_conns_per_ip", required_argument, nullptr, 'i' }, "Maximum number of connections per one IP (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))" },
    { { "log", required_argument, nullptr, 'l' }, "Log file (default: use log_fd)" },
    { { "log_fd", required_argument, nullptr, 'L' }, "Log FD (default: 2)" },
    { { "time_limit", required_argument, nullptr, 't' }, "Maximum time that a jail can exist, in seconds (default: 600)" },
    { { "max_cpus", required_argument, nullptr, 0x508 }, "Maximum number of CPUs a single jailed process can use (default: 0 'no limit')" },
    { { "daemon", no_argument, nullptr, 'd' }, "Daemonize after start" },
    { { "verbose", no_argument, nullptr, 'v' }, "Verbose output" },
    { { "quiet", no_argument, nullptr, 'q' }, "Log warning and more important messages only" },
    { { "really_quiet", no_argument, nullptr, 'Q' }, "Log fatal messages only" },
    { { "keep_env", no_argument, nullptr, 'e' }, "Pass all environment variables to the child process (default: all envars are cleared)" },
    { { "env", required_argument, nullptr, 'E' }, "Additional environment variable (can be used multiple times). If the envar doesn't contain '=' (e.g. just the 'DISPLAY' string), the current envar value will be used" },
    { { "keep_caps", no_argument, nullptr, 0x0501 }, "Don't drop any capabilities" },
    { { "cap", required_argument, nullptr, 0x0509 }, "Retain this capability, e.g. CAP_PTRACE (can be specified multiple times)" },
    { { "silent", no_argument, nullptr, 0x0502 }, "Redirect child process' fd:0/1/2 to /dev/null" },
    { { "stderr_to_null", no_argument, nullptr, 0x0503 }, "Redirect child process' fd:2 (STDERR_FILENO) to /dev/null" },
    { { "skip_setsid", no_argument, nullptr, 0x0504 }, "Don't call setsid(), allows for terminal signal handling in the sandboxed process. Dangerous" },
    { { "pass_fd", required_argument, nullptr, 0x0505 }, "Don't close this FD before executing the child process (can be specified multiple times), by default: 0/1/2 are kept open" },
    { { "disable_no_new_privs", no_argument, nullptr, 0x0507 }, "Don't set the prctl(NO_NEW_PRIVS, 1) (DANGEROUS)" },
    { { "rlimit_as", required_argument, nullptr, 0x0201 }, "RLIMIT_AS in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 4096)" },
    { { "rlimit_core", required_argument, nullptr, 0x0202 }, "RLIMIT_CORE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 0)" },
    { { "rlimit_cpu", required_argument, nullptr, 0x0203 }, "RLIMIT_CPU, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 600)" },
    { { "rlimit_fsize", required_argument, nullptr, 0x0204 }, "RLIMIT_FSIZE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 1)" },
    { { "rlimit_nofile", required_argument, nullptr, 0x0205 }, "RLIMIT_NOFILE, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 32)" },
    { { "rlimit_nproc", required_argument, nullptr, 0x0206 }, "RLIMIT_NPROC, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_stack", required_argument, nullptr, 0x0207 }, "RLIMIT_STACK in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_memlock", required_argument, nullptr, 0x0209 }, "RLIMIT_MEMLOCK in KB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_rtprio", required_argument, nullptr, 0x0210 }, "RLIMIT_RTPRIO, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "rlimit_msgqueue", required_argument, nullptr, 0x0211 }, "RLIMIT_MSGQUEUE in bytes, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')" },
    { { "disable_rlimits", no_argument, nullptr, 0x0208 }, "Disable all rlimits, default to limits set by parent" },
    { { "persona_addr_compat_layout", no_argument, nullptr, 0x0301 }, "personality(ADDR_COMPAT_LAYOUT)" },
    { { "persona_mmap_page_zero", no_argument, nullptr, 0x0302 }, "personality(MMAP_PAGE_ZERO)" },
    { { "persona_read_implies_exec", no_argument, nullptr, 0x0303 }, "personality(READ_IMPLIES_EXEC)" },
    { { "persona_addr_limit_3gb", no_argument, nullptr, 0x0304 }, "personality(ADDR_LIMIT_3GB)" },
    { { "persona_addr_no_randomize", no_argument, nullptr, 0x0305 }, "personality(ADDR_NO_RANDOMIZE)" },
    { { "disable_clone_newnet", no_argument, nullptr, 'N' }, "Don't use CLONE_NEWNET. Enable global networking inside the jail" },
    { { "disable_clone_newuser", no_argument, nullptr, 0x0402 }, "Don't use CLONE_NEWUSER. Requires euid==0" },
    { { "disable_clone_newns", no_argument, nullptr, 0x0403 }, "Don't use CLONE_NEWNS" },
    { { "disable_clone_newpid", no_argument, nullptr, 0x0404 }, "Don't use CLONE_NEWPID" },
    { { "disable_clone_newipc", no_argument, nullptr, 0x0405 }, "Don't use CLONE_NEWIPC" },
    { { "disable_clone_newuts", no_argument, nullptr, 0x0406 }, "Don't use CLONE_NEWUTS" },
    { { "disable_clone_newcgroup", no_argument, nullptr, 0x0407 }, "Don't use CLONE_NEWCGROUP. Might be required for kernel versions < 4.6" },
    { { "enable_clone_newtime", no_argument, nullptr, 0x0408 }, "Use CLONE_NEWTIME. Supported with kernel versions >= 5.3" },
    { { "uid_mapping", required_argument, nullptr, 'U' }, "Add a custom uid mapping of the form inside_uid:outside_uid:count. Setting this requires newuidmap (set-uid) to be present" },
    { { "gid_mapping", required_argument, nullptr, 'G' }, "Add a custom gid mapping of the form inside_gid:outside_gid:count. Setting this requires newgidmap (set-uid) to be present" },
    { { "bindmount_ro", required_argument, nullptr, 'R' }, "List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "bindmount", required_argument, nullptr, 'B' }, "List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'" },
    { { "tmpfsmount", required_argument, nullptr, 'T' }, "List of mountpoints to be mounted as tmpfs (R/W) inside the container. Can be specified multiple times. Supports 'dest' syntax. Alternatively, use '-m none:dest:tmpfs:size=8388608'" },
    { { "mount", required_argument, nullptr, 'm' }, "Arbitrary mount, format src:dst:fs_type:options" },
    { { "symlink", required_argument, nullptr, 's' }, "Symlink, format src:dst" },
    { { "disable_proc", no_argument, nullptr, 0x0603 }, "Disable mounting procfs in the jail" },
    { { "proc_path", required_argument, nullptr, 0x0605 }, "Path used to mount procfs (default: '/proc')" },
    { { "proc_rw", no_argument, nullptr, 0x0606 }, "Is procfs mounted as R/W (default: R/O)" },
    { { "seccomp_policy", required_argument, nullptr, 'P' }, "Path to file containing seccomp-bpf policy (see kafel/)" },
    { { "seccomp_string", required_argument, nullptr, 0x0901 }, "String with kafel seccomp-bpf policy (see kafel/)" },
    { { "seccomp_log", no_argument, nullptr, 0x0902 }, "Use SECCOMP_FILTER_FLAG_LOG. Log all actions except SECCOMP_RET_ALLOW). Supported since kernel version 4.14" },
    { { "nice_level", required_argument, nullptr, 0x0903 }, "Set jailed process niceness (-20 is highest -priority, 19 is lowest). By default, set to 19" },
    { { "cgroup_mem_max", required_argument, nullptr, 0x0801 }, "Maximum number of bytes to use in the group (default: '0' - disabled)" },
    { { "cgroup_mem_memsw_max", required_argument, nullptr, 0x0804 }, "Maximum number of memory+swap bytes to use (default: '0' - disabled)" },
    { { "cgroup_mem_swap_max", required_argument, nullptr, 0x0805 }, "Maximum number of swap bytes to use (default: '-1' - disabled)" },
    { { "cgroup_mem_mount", required_argument, nullptr, 0x0802 }, "Location of memory cgroup FS (default: '/sys/fs/cgroup/memory')" },
    { { "cgroup_mem_parent", required_argument, nullptr, 0x0803 }, "Which pre-existing memory cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_pids_max", required_argument, nullptr, 0x0811 }, "Maximum number of pids in a cgroup (default: '0' - disabled)" },
    { { "cgroup_pids_mount", required_argument, nullptr, 0x0812 }, "Location of pids cgroup FS (default: '/sys/fs/cgroup/pids')" },
    { { "cgroup_pids_parent", required_argument, nullptr, 0x0813 }, "Which pre-existing pids cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_net_cls_classid", required_argument, nullptr, 0x0821 }, "Class identifier of network packets in the group (default: '0' - disabled)" },
    { { "cgroup_net_cls_mount", required_argument, nullptr, 0x0822 }, "Location of net_cls cgroup FS (default: '/sys/fs/cgroup/net_cls')" },
    { { "cgroup_net_cls_parent", required_argument, nullptr, 0x0823 }, "Which pre-existing net_cls cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroup_cpu_ms_per_sec", required_argument, nullptr, 0x0831 }, "Number of milliseconds of CPU time per second that the process group can use (default: '0' - no limit)" },
    { { "cgroup_cpu_mount", required_argument, nullptr, 0x0832 }, "Location of cpu cgroup FS (default: '/sys/fs/cgroup/cpu')" },
    { { "cgroup_cpu_parent", required_argument, nullptr, 0x0833 }, "Which pre-existing cpu cgroup to use as a parent (default: 'NSJAIL')" },
    { { "cgroupv2_mount", required_argument, nullptr, 0x0834}, "Location of cgroupv2 directory (default: '/sys/fs/cgroup')"},
    { { "use_cgroupv2", no_argument, nullptr, 0x0835}, "Use cgroup v2"},
    { { "detect_cgroupv2", no_argument, nullptr, 0x0836}, "Use cgroupv2, if it is available. (Specify instead of use_cgroupv2)"},
    { { "iface_no_lo", no_argument, nullptr, 0x700 }, "Don't bring the 'lo' interface up" },
    { { "iface_own", required_argument, nullptr, 0x704 }, "Move this existing network interface into the new NET namespace. Can be specified multiple times" },
    { { "macvlan_iface", required_argument, nullptr, 'I' }, "Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'" },
    { { "macvlan_vs_ip", required_argument, nullptr, 0x701 }, "IP of the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "macvlan_vs_nm", required_argument, nullptr, 0x702 }, "Netmask of the 'vs' interface (e.g. \"255.255.255.0\")" },
    { { "macvlan_vs_gw", required_argument, nullptr, 0x703 }, "Default GW for the 'vs' interface (e.g. \"192.168.0.1\")" },
    { { "macvlan_vs_ma", required_argument, nullptr, 0x705 }, "MAC-address of the 'vs' interface (e.g. \"ba:ad:ba:be:45:00\")" },
    { { "macvlan_vs_mo", required_argument, nullptr, 0x706 }, "Mode of the 'vs' interface. Can be either 'private', 'vepa', 'bridge' or 'passthru' (default: 'private')" },
    { { "disable_tsc", no_argument, nullptr, 0x707 }, "Disable rdtsc and rdtscp instructions. WARNING: To make it effective, you also need to forbid `prctl(PR_SET_TSC, PR_TSC_ENABLE, ...)` in seccomp rules! (x86 and x86_64 only). Dynamic binaries produced by GCC seem to rely on RDTSC, but static ones should work." },
    { { "forward_signals", no_argument, nullptr, 0x708 }, "Forward fatal signals to the child process instead of always using SIGKILL." },
    { { "use_pasta", no_argument, nullptr, 0x709 }, "Use pasta (user-mode networking) to provide networking connectivity" },
};
// clang-format on

static const char* logYesNo(bool yes) {
	return (yes ? "true" : "false");
}

size_t GetConsoleLength(const std::string& str) {
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

std::string FormatLine(const std::string& line, size_t max_len = 80) {
	std::string indent = line.substr(0, line.find_first_not_of(" \t"));
	size_t indent_len = GetConsoleLength(indent);
	size_t cursor = 0;
	std::string formatted;
	std::vector<std::string> words = util::strSplit(line.c_str(), ' ');
	for (const auto& word : words) {
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

std::string FormatDescription(const char* descr) {
	std::string formatted;
	std::vector<std::string> lines = util::strSplit(descr, '\n');

	for (const auto& line : lines) {
		util::StrAppend(&formatted, "%s\n", FormatLine(std::string("\t") + line).c_str());
	}
	return formatted;
}

static void cmdlineOptUsage(const struct custom_option* option) {
	if (option->opt.val < 0x80) {
		LOG_HELP_BOLD(" --%s%s%c %s", option->opt.name, "|-", option->opt.val,
		    option->opt.has_arg == required_argument ? "VALUE" : "");
	} else {
		LOG_HELP_BOLD(" --%s %s", option->opt.name,
		    option->opt.has_arg == required_argument ? "VALUE" : "");
	}
	LOG_HELP("%s", FormatDescription(option->descr).c_str());
}

static void cmdlineUsage(const char* pname) {
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

void addEnv(nsj_t* nsj, const std::string& env) {
	if (env.find('=') != std::string::npos) {
		nsj->njc.add_envar(env);
		return;
	}
	char* e = getenv(env.c_str());
	if (!e) {
		LOG_W("Requested to use the %s envar, but it's not set. It'll be ignored", QC(env));
		return;
	}
	nsj->njc.add_envar(std::string(env).append("=").append(e));
}

void logParams(nsj_t* nsj) {
	switch (nsj->njc.mode()) {
	case nsjail::Mode::LISTEN:
		LOG_I("Mode: LISTEN_TCP");
		break;
	case nsjail::Mode::ONCE:
		LOG_I("Mode: STANDALONE_ONCE");
		break;
	case nsjail::Mode::EXECVE:
		LOG_I("Mode: STANDALONE_EXECVE");
		break;
	case nsjail::Mode::RERUN:
		LOG_I("Mode: STANDALONE_RERUN");
		break;
	default:
		LOG_F("Mode: UNKNOWN");
		break;
	}

	LOG_I("Jail parameters: hostname:'%s', chroot:%s, process:'%s', "
	      "bind:[%s]:%d, "
	      "max_conns:%u, max_conns_per_ip:%u, time_limit:%u, daemonize:%s, clone_newnet:%s, "
	      "clone_newuser:%s, clone_newns:%s, clone_newpid:%s, clone_newipc:%s, "
	      "clone_newuts:%s, cgroupv2:%s, keep_caps:%s, "
	      "disable_no_new_privs:%s, max_cpus:%u",
	    nsj->njc.hostname().c_str(), QC(nsj->chroot),
	    nsj->njc.exec_bin().path().empty() ? nsj->argv[0].c_str()
					       : nsj->njc.exec_bin().path().c_str(),
	    nsj->njc.bindhost().c_str(), nsj->njc.port(), nsj->njc.max_conns(),
	    nsj->njc.max_conns_per_ip(), nsj->njc.time_limit(), logYesNo(nsj->njc.daemon()),
	    logYesNo(nsj->njc.clone_newnet()), logYesNo(nsj->njc.clone_newuser()),
	    logYesNo(nsj->njc.clone_newns()), logYesNo(nsj->njc.clone_newpid()),
	    logYesNo(nsj->njc.clone_newipc()), logYesNo(nsj->njc.clone_newuts()),
	    logYesNo(nsj->njc.use_cgroupv2()), logYesNo(nsj->njc.keep_caps()),
	    logYesNo(nsj->njc.disable_no_new_privs()), nsj->njc.max_cpus());

	for (const auto& p : nsj->njc.mount()) {
		LOG_I("%s: %s", p.is_symlink() ? "Symlink" : "Mount",
		    mnt::describeMountPt(p).c_str());
	}
	for (const auto& uid : nsj->uids) {
		LOG_I("Uid map: inside_uid:%lu outside_uid:%lu count:%zu newuidmap:%s",
		    (unsigned long)uid.inside_id, (unsigned long)uid.outside_id, uid.count,
		    uid.is_newidmap ? "true" : "false");
		if (uid.outside_id == 0 && nsj->njc.clone_newuser()) {
			LOG_W("Process will be UID/EUID=0 in the global user namespace, and "
			      "will "
			      "have user root-level access to files");
		}
	}
	for (const auto& gid : nsj->gids) {
		LOG_I("Gid map: inside_gid:%lu outside_gid:%lu count:%zu newgidmap:%s",
		    (unsigned long)gid.inside_id, (unsigned long)gid.outside_id, gid.count,
		    gid.is_newidmap ? "true" : "false");
		if (gid.outside_id == 0 && nsj->njc.clone_newuser()) {
			LOG_W("Process will be GID/EGID=0 in the global user namespace, and "
			      "will "
			      "have group root-level access to files");
		}
	}
}

uint64_t parseRLimit(int res, const char* optarg, unsigned long mul) {
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
		LOG_F("RLIMIT %s (%d) needs a numeric value or 'max'/'hard'/'def'/'soft'/'inf' "
		      "value (%s provided)",
		    util::rLimName(res).c_str(), res, QC(optarg));
	}
	errno = 0;
	uint64_t val = strtoull(optarg, NULL, 0);
	if (val == ULLONG_MAX && errno != 0) {
		PLOG_F("strtoull('%s', 0)", optarg);
	}
	return val * mul;
}

static std::string argFromVec(const std::vector<std::string>& vec, size_t pos) {
	if (pos >= vec.size()) {
		return "";
	}
	return vec[pos];
}

static bool setupArgv(nsj_t* nsj, int argc, char** argv, int optind) {
	/*
	 * If user provided cmdline via nsjail [opts] -- [cmdline], then override
	 * the one from the config file
	 */
	if (optind < argc) {
		nsj->argv.clear();
		for (int i = optind; i < argc; i++) {
			nsj->argv.push_back(argv[i]);
		}
	}
	if (!nsj->njc.exec_bin().has_path() && !nsj->argv.empty()) {
		nsj->njc.mutable_exec_bin()->set_path(nsj->argv[0]);
	}
	if (!nsj->njc.exec_bin().has_path()) {
		cmdlineUsage(argv[0]);
		LOG_E("No command-line provided");
		return false;
	}

	if (nsj->njc.exec_bin().exec_fd()) {
#if !defined(__NR_execveat)
		LOG_E("Your nsjail is compiled without support for the execveat() "
		      "syscall, "
		      "yet you "
		      "specified the --execute_fd flag");
		return false;
#endif /* !defined(__NR_execveat) */
		if ((nsj->exec_fd = TEMP_FAILURE_RETRY(open(nsj->njc.exec_bin().path().c_str(),
			 O_RDONLY | O_PATH | O_CLOEXEC))) == -1) {
			PLOG_W("Couldn't open %s file", QC(nsj->njc.exec_bin().path()));
			return false;
		}
	}
	return true;
}

static bool setupMounts(nsj_t* nsj) {
	if (!(nsj->chroot.empty())) {
		nsjail::MountPt* p = nsj->njc.add_mount();
		p->set_src(nsj->chroot);
		p->set_dst("/");
		p->set_is_bind(true);
		p->set_rw(nsj->is_root_rw);
		p->set_is_dir(true);
		/* Insert at the beginning */
		for (int i = nsj->njc.mount_size() - 1; i > 0; i--) {
			nsj->njc.mutable_mount()->SwapElements(i, i - 1);
		}
	} else {
		nsjail::MountPt* p = nsj->njc.add_mount();
		p->set_dst("/");
		p->set_fstype("tmpfs");
		p->set_rw(nsj->is_root_rw);
		p->set_is_dir(true);
		/* Insert at the beginning */
		for (int i = nsj->njc.mount_size() - 1; i > 0; i--) {
			nsj->njc.mutable_mount()->SwapElements(i, i - 1);
		}
	}
	if (!nsj->proc_path.empty()) {
		nsjail::MountPt* p = nsj->njc.add_mount();
		p->set_dst(nsj->proc_path);
		p->set_fstype("proc");
		p->set_rw(nsj->njc.mount_proc());
		p->set_is_dir(true);
	}

	return true;
}

void setupUsers(nsj_t* nsj) {
	if (nsj->uids.empty()) {
		idmap_t uid;
		uid.inside_id = getuid();
		uid.outside_id = getuid();
		uid.count = 1U;
		uid.is_newidmap = false;
		nsj->uids.push_back(uid);
	}
	if (nsj->gids.empty()) {
		idmap_t gid;
		gid.inside_id = getgid();
		gid.outside_id = getgid();
		gid.count = 1U;
		gid.is_newidmap = false;
		nsj->gids.push_back(gid);
	}
}

std::string parseMACVlanMode(const char* optarg) {
	if (strcasecmp(optarg, "private") != 0 && strcasecmp(optarg, "vepa") != 0 &&
	    strcasecmp(optarg, "bridge") != 0 && strcasecmp(optarg, "passthru") != 0) {
		LOG_F("macvlan mode can only be one of the values: "
		      "'private'/'vepa'/'bridge'/'passthru' ('%s' "
		      "provided).",
		    optarg);
	}
	return std::string(optarg);
}

std::unique_ptr<nsj_t> parseArgs(int argc, char* argv[]) {
	std::unique_ptr<nsj_t> nsj(new nsj_t);

	nsj->is_root_rw = false;
	nsj->is_proc_rw = false;
	nsj->proc_path = "/proc";
	nsj->orig_uid = getuid();
	nsj->orig_euid = geteuid();
	nsj->seccomp_fprog.filter = NULL;
	nsj->seccomp_fprog.len = 0;

	nsj->openfds.push_back(STDIN_FILENO);
	nsj->openfds.push_back(STDOUT_FILENO);
	nsj->openfds.push_back(STDERR_FILENO);

	/* Generate options array for getopt_long. */
	const size_t options_length = ARR_SZ(custom_opts) + 1;
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
			nsj->njc.mutable_exec_bin()->set_path(optarg);
			break;
		case 'H':
			nsj->njc.set_hostname(optarg);
			break;
		case 'D':
			nsj->njc.set_cwd(optarg);
			break;
		case 'C':
			if (!config::parseFile(nsj.get(), optarg)) {
				LOG_F("Couldn't parse configuration from %s file", QC(optarg));
			}
			break;
		case 'c':
			nsj->chroot = optarg;
			break;
		case 'p':
			if (!util::isANumber(optarg)) {
				LOG_E("Couldn't parse TCP port '%s'", optarg);
				return nullptr;
			}
			nsj->njc.set_port(strtoumax(optarg, NULL, 0));
			nsj->njc.set_mode(nsjail::Mode::LISTEN);
			break;
		case 0x604:
			nsj->njc.set_bindhost(optarg);
			break;
		case 0x608:
			nsj->njc.set_max_conns(strtoul(optarg, NULL, 0));
			break;
		case 'i':
			nsj->njc.set_max_conns_per_ip(strtoul(optarg, NULL, 0));
			break;
		case 'l':
			logs::logFile(optarg, STDERR_FILENO);
			break;
		case 'L':
			logs::logFile("", std::strtol(optarg, NULL, 0));
			break;
		case 'd':
			nsj->njc.set_daemon(true);
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
			nsj->njc.set_keep_env(true);
			break;
		case 't':
			nsj->njc.set_time_limit((uint64_t)strtoull(optarg, NULL, 0));
			break;
		case 'h': /* help */
			logs::logFile("", STDOUT_FILENO);
			cmdlineUsage(argv[0]);
			exit(0);
			break;
		case 0x0201:
			nsj->njc.set_rlimit_as(parseRLimit(RLIMIT_AS, optarg, 1));
			nsj->njc.set_rlimit_as_type(nsjail::RLimit::VALUE);
			break;
		case 0x0202:
			nsj->njc.set_rlimit_core(parseRLimit(RLIMIT_CORE, optarg, 1));
			nsj->njc.set_rlimit_core_type(nsjail::RLimit::VALUE);
			break;
		case 0x0203:
			nsj->njc.set_rlimit_cpu(parseRLimit(RLIMIT_CPU, optarg, 1));
			nsj->njc.set_rlimit_cpu_type(nsjail::RLimit::VALUE);
			break;
		case 0x0204:
			nsj->njc.set_rlimit_fsize(parseRLimit(RLIMIT_FSIZE, optarg, 1));
			nsj->njc.set_rlimit_fsize_type(nsjail::RLimit::VALUE);
			break;
		case 0x0205:
			nsj->njc.set_rlimit_nofile(parseRLimit(RLIMIT_NOFILE, optarg, 1));
			nsj->njc.set_rlimit_nofile_type(nsjail::RLimit::VALUE);
			break;
		case 0x0206:
			nsj->njc.set_rlimit_nproc(parseRLimit(RLIMIT_NPROC, optarg, 1));
			nsj->njc.set_rlimit_nproc_type(nsjail::RLimit::VALUE);
			break;
		case 0x0207:
			nsj->njc.set_rlimit_stack(parseRLimit(RLIMIT_STACK, optarg, 1));
			nsj->njc.set_rlimit_stack_type(nsjail::RLimit::VALUE);
			break;
		case 0x0209:
			nsj->njc.set_rlimit_memlock(parseRLimit(RLIMIT_MEMLOCK, optarg, 1));
			nsj->njc.set_rlimit_memlock_type(nsjail::RLimit::VALUE);
			break;
		case 0x0210:
			nsj->njc.set_rlimit_rtprio(parseRLimit(RLIMIT_RTPRIO, optarg, 1));
			nsj->njc.set_rlimit_rtprio_type(nsjail::RLimit::VALUE);
			break;
		case 0x0211:
			nsj->njc.set_rlimit_msgqueue(parseRLimit(RLIMIT_MSGQUEUE, optarg, 1));
			nsj->njc.set_rlimit_msgqueue_type(nsjail::RLimit::VALUE);
			break;
		case 0x0208:
			nsj->njc.set_disable_rl(true);
			break;
		case 0x0301:
			nsj->njc.set_persona_addr_compat_layout(true);
			break;
		case 0x0302:
			nsj->njc.set_persona_mmap_page_zero(true);
			break;
		case 0x0303:
			nsj->njc.set_persona_read_implies_exec(true);
			break;
		case 0x0304:
			nsj->njc.set_persona_addr_limit_3gb(true);
			break;
		case 0x0305:
			nsj->njc.set_persona_addr_no_randomize(true);
			break;
		case 'N':
			nsj->njc.set_clone_newnet(false);
			break;
		case 0x0402:
			nsj->njc.set_clone_newuser(false);
			break;
		case 0x0403:
			nsj->njc.set_clone_newns(false);
			break;
		case 0x0404:
			nsj->njc.set_clone_newpid(false);
			break;
		case 0x0405:
			nsj->njc.set_clone_newipc(false);
			break;
		case 0x0406:
			nsj->njc.set_clone_newuts(false);
			break;
		case 0x0407:
			nsj->njc.set_clone_newcgroup(false);
			break;
		case 0x0408:
			nsj->njc.set_clone_newtime(true);
			break;
		case 0x0501:
			nsj->njc.set_keep_caps(true);
			break;
		case 0x0502:
			nsj->njc.set_silent(true);
			break;
		case 0x0503:
			nsj->njc.set_stderr_to_null(true);
			break;
		case 0x0504:
			nsj->njc.set_skip_setsid(true);
			break;
		case 0x0505:
			nsj->openfds.push_back((int)strtol(optarg, NULL, 0));
			break;
		case 0x0507:
			nsj->njc.set_disable_no_new_privs(true);
			break;
		case 0x0508:
			nsj->njc.set_max_cpus(strtoul(optarg, NULL, 0));
			break;
		case 0x0509: {
			int cap = caps::nameToVal(optarg);
			if (cap == -1) {
				return nullptr;
			}

			nsj->njc.add_cap(optarg);
		} break;
		case 0x0600:
			nsj->njc.set_no_pivotroot(true);
			break;
		case 0x0601:
			nsj->is_root_rw = true;
			break;
		case 0x0603:
			nsj->njc.set_mount_proc(false);
			nsj->proc_path.clear();
			break;
		case 0x0605:
			nsj->njc.set_mount_proc(true);
			nsj->proc_path = optarg;

			break;
		case 0x0606:
			nsj->is_proc_rw = true;
			break;
		case 0x0607:
			nsj->njc.mutable_exec_bin()->set_exec_fd(true);
			break;
		case 'E':
			addEnv(nsj.get(), optarg);
			break;
		case 0x709:
			nsj->njc.mutable_user_net()->set_enable(true);
			break;
		case 'u': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string i_id = argFromVec(subopts, 0);
			std::string o_id = argFromVec(subopts, 1);
			std::string cnt = argFromVec(subopts, 2);
			size_t count = strtoul(cnt.c_str(), nullptr, 0);
			if (!user::parseId(nsj.get(), i_id, o_id, count,
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
			if (!user::parseId(nsj.get(), i_id, o_id, count,
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
			if (!user::parseId(nsj.get(), i_id, o_id, count,
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
			if (!user::parseId(nsj.get(), i_id, o_id, count,
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
			nsjail::MountPt* p = nsj->njc.add_mount();
			p->set_src(src);
			p->set_dst(dst);
			p->set_rw(false);
			p->set_is_bind(true);
		} break;
		case 'B': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (dst.empty()) {
				dst = src;
			}
			std::string options = argFromVec(subopts, 2);
			nsjail::MountPt* p = nsj->njc.add_mount();
			p->set_src(src);
			p->set_dst(dst);
			p->set_options(options);
			p->set_rw(true);
			p->set_is_bind(true);
		} break;
		case 'T': {
			nsjail::MountPt* p = nsj->njc.add_mount();
			p->set_dst(optarg);
			p->set_fstype("tmpfs");
			p->set_options("size=4194304");
			p->set_rw(true);
			p->set_is_dir(true);
		} break;
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
			nsjail::MountPt* p = nsj->njc.add_mount();
			p->set_src(src);
			p->set_dst(dst);
			p->set_fstype(fs_type);
			p->set_options(options);
			p->set_rw(true);
		} break;
		case 's': {
			std::vector<std::string> subopts = util::strSplit(optarg, ':');
			std::string src = argFromVec(subopts, 0);
			std::string dst = argFromVec(subopts, 1);
			if (dst.empty()) {
				dst = src;
			}
			nsjail::MountPt* p = nsj->njc.add_mount();
			p->set_src(src);
			p->set_dst(dst);
			p->set_is_symlink(true);
			p->set_rw(true);
		} break;
		case 'M':
			switch (optarg[0]) {
			case 'l':
				nsj->njc.set_mode(nsjail::Mode::LISTEN);
				break;
			case 'o':
				nsj->njc.set_mode(nsjail::Mode::ONCE);
				break;
			case 'e':
				nsj->njc.set_mode(nsjail::Mode::EXECVE);
				break;
			case 'r':
				nsj->njc.set_mode(nsjail::Mode::RERUN);
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
			nsj->njc.set_iface_no_lo(true);
			break;
		case 'I':
			nsj->njc.set_macvlan_iface(optarg);
			break;
		case 0x701:
			nsj->njc.set_macvlan_vs_ip(optarg);
			break;
		case 0x702:
			nsj->njc.set_macvlan_vs_nm(optarg);
			break;
		case 0x703:
			nsj->njc.set_macvlan_vs_gw(optarg);
			break;
		case 0x704:
			nsj->njc.add_iface_own(optarg);
			break;
		case 0x705:
			nsj->njc.set_macvlan_vs_ma(optarg);
			break;
		case 0x706:
			nsj->njc.set_macvlan_vs_mo(parseMACVlanMode(optarg));
			break;
		case 0x707:
			nsj->njc.set_disable_tsc(true);
			break;
		case 0x708:
			nsj->njc.set_forward_signals(true);
			break;
		case 0x801:
			nsj->njc.set_cgroup_mem_max((size_t)strtoull(optarg, NULL, 0));
			break;
		case 0x802:
			nsj->njc.set_cgroup_mem_mount(optarg);
			break;
		case 0x803:
			nsj->njc.set_cgroup_mem_parent(optarg);
			break;
		case 0x804:
			nsj->njc.set_cgroup_mem_memsw_max((size_t)strtoull(optarg, NULL, 0));
			break;
		case 0x805:
			nsj->njc.set_cgroup_mem_swap_max((ssize_t)strtoll(optarg, NULL, 0));
			break;
		case 0x811:
			nsj->njc.set_cgroup_pids_max((unsigned int)strtoul(optarg, NULL, 0));
			break;
		case 0x812:
			nsj->njc.set_cgroup_pids_mount(optarg);
			break;
		case 0x813:
			nsj->njc.set_cgroup_pids_parent(optarg);
			break;
		case 0x821:
			nsj->njc.set_cgroup_net_cls_classid((unsigned int)strtoul(optarg, NULL, 0));
			break;
		case 0x822:
			nsj->njc.set_cgroup_net_cls_mount(optarg);
			break;
		case 0x823:
			nsj->njc.set_cgroup_net_cls_parent(optarg);
			break;
		case 0x831:
			nsj->njc.set_cgroup_cpu_ms_per_sec((unsigned int)strtoul(optarg, NULL, 0));
			break;
		case 0x832:
			nsj->njc.set_cgroup_cpu_mount(optarg);
			break;
		case 0x833:
			nsj->njc.set_cgroup_cpu_parent(optarg);
			break;
		case 0x834:
			nsj->njc.set_cgroupv2_mount(optarg);
			break;
		case 0x835:
			nsj->njc.set_use_cgroupv2(true);
			break;
		case 0x836:
			nsj->njc.set_detect_cgroupv2(true);
			break;
		case 'P':
			nsj->njc.set_seccomp_policy_file(optarg);
			break;
		case 0x901:
			nsj->njc.add_seccomp_string(optarg);
			break;
		case 0x902:
			nsj->njc.set_seccomp_log(true);
			break;
		case 0x903:
			nsj->njc.set_nice_level((int)strtol(optarg, NULL, 0));
			break;
		default:
			cmdlineUsage(argv[0]);
			return nullptr;
			break;
		}
	}

	if (nsj->njc.daemon() && !logs::logSet()) {
		logs::logFile(_LOG_DEFAULT_FILE, STDERR_FILENO);
	}
	if (!setupMounts(nsj.get())) {
		return nullptr;
	}
	if (!setupArgv(nsj.get(), argc, argv, optind)) {
		return nullptr;
	}
	setupUsers(nsj.get());

	if (nsj->njc.cgroup_mem_memsw_max() > (size_t)0 &&
	    nsj->njc.cgroup_mem_swap_max() >= (ssize_t)0) {
		LOG_F("cannot set both cgroup_mem_memsw_max and cgroup_mem_swap_max");
	}

	return nsj;
}

}  // namespace cmdline
