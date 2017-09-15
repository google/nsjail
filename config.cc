/*

   nsjail - config parsing
   -----------------------------------------

   Copyright 2017 Google Inc. All Rights Reserved.

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

extern "C" {
#include "common.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "caps.h"
#include "config.h"
#include "log.h"
#include "mount.h"
#include "user.h"
#include "util.h"
}

#include <fstream>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <string>

#include "config.pb.h"

#define DUP_IF_SET(njc, val) (njc.has_##val() ? utilStrDup(njc.val().c_str()) : NULL)

static bool configParseInternal(struct nsjconf_t* nsjconf,
    const nsjail::NsJailConfig& njc)
{
    switch (njc.mode()) {
    case nsjail::Mode::LISTEN:
        nsjconf->mode = MODE_LISTEN_TCP;
        break;
    case nsjail::Mode::ONCE:
        nsjconf->mode = MODE_STANDALONE_ONCE;
        break;
    case nsjail::Mode::RERUN:
        nsjconf->mode = MODE_STANDALONE_RERUN;
        break;
    case nsjail::Mode::EXECVE:
        nsjconf->mode = MODE_STANDALONE_EXECVE;
        break;
    default:
        LOG_E("Uknown running mode: %d", njc.mode());
        return false;
    }
    nsjconf->chroot = DUP_IF_SET(njc, chroot_dir);
    nsjconf->is_root_rw = njc.is_root_rw();
    nsjconf->hostname = DUP_IF_SET(njc, hostname);
    nsjconf->cwd = DUP_IF_SET(njc, cwd);
    nsjconf->port = njc.port();
    nsjconf->bindhost = DUP_IF_SET(njc, bindhost);
    nsjconf->max_conns_per_ip = njc.max_conns_per_ip();
    nsjconf->tlimit = njc.time_limit();
    nsjconf->max_cpus = njc.max_cpus();
    nsjconf->daemonize = njc.daemon();

    if (njc.has_log_fd()) {
        nsjconf->log_fd = njc.log_fd();
    }
    nsjconf->logfile = DUP_IF_SET(njc, log_file);
    if (njc.has_log_level()) {
        switch (njc.log_level()) {
        case nsjail::LogLevel::DEBUG:
            nsjconf->loglevel = DEBUG;
            break;
        case nsjail::LogLevel::INFO:
            nsjconf->loglevel = INFO;
            break;
        case nsjail::LogLevel::WARNING:
            nsjconf->loglevel = WARNING;
            break;
        case nsjail::LogLevel::ERROR:
            nsjconf->loglevel = ERROR;
            break;
        case nsjail::LogLevel::FATAL:
            nsjconf->loglevel = FATAL;
            break;
        default:
            LOG_E("Unknown log_level: %d", njc.log_level());
            return false;
        }
    }

    if (njc.has_log_fd() || njc.has_log_file() || njc.has_log_level()) {
        if (logInitLogFile(nsjconf) == false) {
            return false;
        }
    }

    nsjconf->keep_env = njc.keep_env();
    for (ssize_t i = 0; i < njc.envar_size(); i++) {
        struct charptr_t* p = reinterpret_cast<charptr_t*>(utilMalloc(sizeof(struct charptr_t)));
        p->val = utilStrDup(njc.envar(i).c_str());
        TAILQ_INSERT_TAIL(&nsjconf->envs, p, pointers);
    }

    nsjconf->keep_caps = njc.keep_caps();
    for (ssize_t i = 0; i < njc.cap_size(); i++) {
        struct ints_t* f = reinterpret_cast<struct ints_t*>(utilMalloc(sizeof(struct ints_t)));
        f->val = capsNameToVal(njc.cap(i).c_str());
        if (f->val == -1) {
            return false;
        }
        TAILQ_INSERT_HEAD(&nsjconf->caps, f, pointers);
    }

    nsjconf->is_silent = njc.silent();
    nsjconf->skip_setsid = njc.skip_setsid();

    for (ssize_t i = 0; i < njc.pass_fd_size(); i++) {
        struct ints_t* f = reinterpret_cast<struct ints_t*>(utilMalloc(sizeof(struct ints_t)));
        f->val = njc.pass_fd(i);
        TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);
    }

    nsjconf->disable_no_new_privs = njc.disable_no_new_privs();

    nsjconf->rl_as = njc.rlimit_as() * 1024ULL * 1024ULL;
    nsjconf->rl_core = njc.rlimit_core() * 1024ULL * 1024ULL;
    nsjconf->rl_cpu = njc.rlimit_cpu();
    nsjconf->rl_fsize = njc.rlimit_fsize() * 1024ULL * 1024ULL;
    nsjconf->rl_nofile = njc.rlimit_nofile();
    if (njc.has_rlimit_nproc()) {
        nsjconf->rl_nproc = njc.rlimit_nproc();
    }
    if (njc.has_rlimit_stack()) {
        nsjconf->rl_stack = njc.rlimit_stack() * 1024ULL * 1024ULL;
    }

    if (njc.persona_addr_compat_layout()) {
        nsjconf->personality |= ADDR_COMPAT_LAYOUT;
    }
    if (njc.persona_mmap_page_zero()) {
        nsjconf->personality |= MMAP_PAGE_ZERO;
    }
    if (njc.persona_read_implies_exec()) {
        nsjconf->personality |= READ_IMPLIES_EXEC;
    }
    if (njc.persona_addr_limit_3gb()) {
        nsjconf->personality |= ADDR_LIMIT_3GB;
    }
    if (njc.persona_addr_no_randomize()) {
        nsjconf->personality |= ADDR_NO_RANDOMIZE;
    }

    nsjconf->clone_newnet = njc.clone_newnet();
    nsjconf->clone_newuser = njc.clone_newuser();
    nsjconf->clone_newns = njc.clone_newns();
    nsjconf->clone_newpid = njc.clone_newpid();
    nsjconf->clone_newipc = njc.clone_newipc();
    nsjconf->clone_newuts = njc.clone_newuts();
    nsjconf->clone_newcgroup = njc.clone_newcgroup();

    for (ssize_t i = 0; i < njc.uidmap_size(); i++) {
        if (userParseId(nsjconf, DUP_IF_SET(njc.uidmap(i), inside_id), DUP_IF_SET(njc.uidmap(i), outside_id),
                njc.uidmap(i).count(), false /* is_gid */,
                njc.uidmap(i).use_newidmap())
            == false) {
            return false;
        }
    }
    for (ssize_t i = 0; i < njc.gidmap_size(); i++) {
        if (userParseId(nsjconf, DUP_IF_SET(njc.gidmap(i), inside_id), DUP_IF_SET(njc.gidmap(i), outside_id),
                njc.gidmap(i).count(), true /* is_gid */,
                njc.gidmap(i).use_newidmap())
            == false) {
            return false;
        }
    }

    nsjconf->mount_proc = njc.mount_proc();
    for (ssize_t i = 0; i < njc.mount_size(); i++) {
        const char* src = (njc.mount(i).has_src()) ? njc.mount(i).src().c_str() : NULL;
        const char* src_env = (njc.mount(i).has_prefix_src_env()) ? njc.mount(i).prefix_src_env().c_str() : NULL;
        const char* dst = (njc.mount(i).has_dst()) ? njc.mount(i).dst().c_str() : NULL;
        const char* dst_env = (njc.mount(i).has_prefix_dst_env()) ? njc.mount(i).prefix_dst_env().c_str() : NULL;
        const char* fstype = (njc.mount(i).has_fstype()) ? njc.mount(i).fstype().c_str() : NULL;
        const char* options = (njc.mount(i).has_options()) ? njc.mount(i).options().c_str() : NULL;

        uintptr_t flags = (njc.mount(i).rw() == false) ? MS_RDONLY : 0;
        flags |= njc.mount(i).is_bind() ? (MS_BIND | MS_REC) : 0;
        bool mandatory = njc.mount(i).mandatory();

        const bool isDir = (njc.mount(i).has_is_dir() && njc.mount(i).is_dir()) ? true : false;
        const bool* isDirPtr = (njc.mount(i).has_is_dir()) ? &isDir : NULL;

        const char* src_content = NULL;
        size_t src_content_len = 0;
        if (njc.mount(i).has_src_content()) {
            src_content = njc.mount(i).src_content().data();
            src_content_len = njc.mount(i).src_content().size();
        }

        if (mountAddMountPt(nsjconf, src, dst, fstype, options, flags, isDirPtr,
                mandatory, src_env, dst_env, src_content,
                src_content_len, njc.mount(i).is_symlink())
            == false) {
            LOG_E("Couldn't add mountpoint for src:'%s' dst:'%s'", src, dst);
            return false;
        }
    }

    if (njc.has_seccomp_policy_file()) {
        if ((nsjconf->kafel_file = fopen(njc.seccomp_policy_file().c_str(), "rb")) == NULL) {
            PLOG_W("Couldn't open file with seccomp policy '%s'",
                njc.seccomp_policy_file().c_str());
            return false;
        }
    }

    std::string kafel_string;
    for (ssize_t i = 0; i < njc.seccomp_string().size(); i++) {
        kafel_string += njc.seccomp_string(i);
    }
    nsjconf->kafel_string = njc.seccomp_string().size() > 0
        ? utilStrDup(kafel_string.c_str())
        : NULL;

    nsjconf->cgroup_mem_max = njc.cgroup_mem_max();
    nsjconf->cgroup_mem_mount = DUP_IF_SET(njc, cgroup_mem_mount);
    nsjconf->cgroup_mem_parent = DUP_IF_SET(njc, cgroup_mem_parent);
    nsjconf->cgroup_pids_max = njc.cgroup_pids_max();
    nsjconf->cgroup_pids_mount = DUP_IF_SET(njc, cgroup_pids_mount);
    nsjconf->cgroup_pids_parent = DUP_IF_SET(njc, cgroup_pids_parent);

    nsjconf->iface_no_lo = njc.iface_no_lo();
    nsjconf->iface_vs = DUP_IF_SET(njc, macvlan_iface);
    nsjconf->iface_vs_ip = DUP_IF_SET(njc, macvlan_vs_ip);
    nsjconf->iface_vs_nm = DUP_IF_SET(njc, macvlan_vs_nm);
    nsjconf->iface_vs_gw = DUP_IF_SET(njc, macvlan_vs_gw);

    if (njc.has_exec_bin()) {
        char** argv = reinterpret_cast<char**>(utilCalloc(sizeof(const char*) * (njc.exec_bin().arg().size() + 2)));
        if (njc.exec_bin().has_arg0()) {
            argv[0] = utilStrDup(njc.exec_bin().arg0().c_str());
        } else {
            argv[0] = utilStrDup(njc.exec_bin().path().c_str());
        }
        for (ssize_t i = 0; i < njc.exec_bin().arg().size(); i++) {
            argv[i + 1] = utilStrDup(njc.exec_bin().arg(i).c_str());
        }
        argv[njc.exec_bin().arg().size() + 1] = NULL;
        nsjconf->exec_file = DUP_IF_SET(njc.exec_bin(), path);
        nsjconf->argv = argv;
    }

    return true;
}

static void LogHandler(google::protobuf::LogLevel level, const char* filename, int line, const std::string& message)
{
    LOG_W("config.cc: '%s'", message.c_str());
}

extern "C" bool configParse(struct nsjconf_t* nsjconf, const char* file)
{
    LOG_I("Parsing configuration from '%s'", file);

    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        PLOG_W("Couldn't open config file '%s'", file);
        return false;
    }

    SetLogHandler(LogHandler);
    google::protobuf::io::FileInputStream input(fd);
    input.SetCloseOnDelete(true);

    nsjail::NsJailConfig nsc;

    auto parser = google::protobuf::TextFormat::Parser();

    if (!parser.Parse(&input, &nsc)) {
        LOG_W("Couldn't parse file '%s' from Text into ProtoBuf", file);
        return false;
    }
    if (!configParseInternal(nsjconf, nsc)) {
        LOG_W("Couldn't parse the ProtoBuf");
        return false;
    }
    LOG_D("Parsed config:\n'%s'", nsc.DebugString().c_str());

    return true;
}
