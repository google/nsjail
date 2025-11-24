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

#include "config.h"

#include <fcntl.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <list>
#include <string>

#include "caps.h"
#include "cmdline.h"
#include "config.pb.h"
#include "logs.h"
#include "macros.h"
#include "mnt.h"
#include "user.h"
#include "util.h"

namespace config {

uint64_t adjustRLimit(int res, const nsjail::RLimit& rl, const uint64_t val, unsigned long mul) {
	if (rl == nsjail::RLimit::VALUE) {
		return (val * mul);
	}
	if (rl == nsjail::RLimit::SOFT) {
		return cmdline::parseRLimit(res, "soft", mul);
	}
	if (rl == nsjail::RLimit::HARD) {
		return cmdline::parseRLimit(res, "hard", mul);
	}
	if (rl == nsjail::RLimit::INF) {
		return RLIM64_INFINITY;
	}
	LOG_F("Unknown rlimit value type for rlimit:%d", res);
	abort();
}

static bool parseInternal(nsj_t* nsj, const nsjail::NsJailConfig& njc) {
	nsj->njc.CopyFrom(njc);
	/*
	 * We need to copy the values from the protobuf message to the internal
	 * struct, because we need to perform some transformations on them.
	 */
	if (njc.has_log_fd()) {
		logs::logFile("", njc.log_fd());
	}
	if (njc.has_log_file()) {
		logs::logFile(njc.log_file(), STDERR_FILENO);
	}

	if (njc.has_log_level()) {
		switch (njc.log_level()) {
		case nsjail::LogLevel::DEBUG:
			logs::setLogLevel(logs::DEBUG);
			break;
		case nsjail::LogLevel::INFO:
			logs::setLogLevel(logs::INFO);
			break;
		case nsjail::LogLevel::WARNING:
			logs::setLogLevel(logs::WARNING);
			break;
		case nsjail::LogLevel::ERROR:
			logs::setLogLevel(logs::ERROR);
			break;
		case nsjail::LogLevel::FATAL:
			logs::setLogLevel(logs::FATAL);
			break;
		default:
			LOG_E("Unknown log_level: %d", njc.log_level());
			return false;
		}
	}

	for (ssize_t i = 0; i < njc.envar_size(); i++) {
		cmdline::addEnv(nsj, njc.envar(i));
	}

	for (ssize_t i = 0; i < njc.cap_size(); i++) {
		int cap = caps::nameToVal(njc.cap(i).c_str());
		if (cap == -1) {
			return false;
		}
		nsj->caps.push_back(cap);
	}

	for (ssize_t i = 0; i < njc.pass_fd_size(); i++) {
		nsj->openfds.push_back(njc.pass_fd(i));
	}

	if (njc.persona_addr_compat_layout()) {
		nsj->personality |= ADDR_COMPAT_LAYOUT;
	}
	if (njc.persona_mmap_page_zero()) {
		nsj->personality |= MMAP_PAGE_ZERO;
	}
	if (njc.persona_read_implies_exec()) {
		nsj->personality |= READ_IMPLIES_EXEC;
	}
	if (njc.persona_addr_limit_3gb()) {
		nsj->personality |= ADDR_LIMIT_3GB;
	}
	if (njc.persona_addr_no_randomize()) {
		nsj->personality |= ADDR_NO_RANDOMIZE;
	}

	for (ssize_t i = 0; i < njc.uidmap_size(); i++) {
		if (!user::parseId(nsj, njc.uidmap(i).inside_id(), njc.uidmap(i).outside_id(),
			njc.uidmap(i).count(), false /* is_gid */, njc.uidmap(i).use_newidmap())) {
			return false;
		}
	}
	for (ssize_t i = 0; i < njc.gidmap_size(); i++) {
		if (!user::parseId(nsj, njc.gidmap(i).inside_id(), njc.gidmap(i).outside_id(),
			njc.gidmap(i).count(), true /* is_gid */, njc.gidmap(i).use_newidmap())) {
			return false;
		}
	}

	if (!njc.mount_proc()) {
		nsj->proc_path.clear();
	}
	for (ssize_t i = 0; i < njc.mount_size(); i++) {
		std::string src = njc.mount(i).src();
		std::string src_env = njc.mount(i).prefix_src_env();
		std::string dst = njc.mount(i).dst();
		std::string dst_env = njc.mount(i).prefix_dst_env();
		std::string fstype = njc.mount(i).fstype();
		std::string options = njc.mount(i).options();

		uintptr_t flags = (!njc.mount(i).rw()) ? MS_RDONLY : 0;
		flags |= njc.mount(i).is_bind() ? (MS_BIND | MS_REC | MS_PRIVATE) : 0;
		flags |= njc.mount(i).nosuid() ? MS_NOSUID : 0;
		flags |= njc.mount(i).nodev() ? MS_NODEV : 0;
		flags |= njc.mount(i).noexec() ? MS_NOEXEC : 0;
		bool is_mandatory = njc.mount(i).mandatory();
		bool is_symlink = njc.mount(i).is_symlink();
		std::string src_content = njc.mount(i).src_content();

		mnt::isDir_t is_dir = mnt::NS_DIR_MAYBE;
		if (njc.mount(i).has_is_dir()) {
			is_dir = njc.mount(i).is_dir() ? mnt::NS_DIR_YES : mnt::NS_DIR_NO;
		}

		if (!mnt::addMountPtTail(nsj, src, dst, fstype, options, flags, is_dir,
			is_mandatory, src_env, dst_env, src_content, is_symlink)) {
			LOG_E("Couldn't add mountpoint for src:%s dst:%s", QC(src), QC(dst));
			return false;
		}
	}

	if (njc.has_seccomp_policy_file()) {
		nsj->njc.set_seccomp_policy_file(njc.seccomp_policy_file());
	}
	/* seccomp_string is handled via nsj->njc.CopyFrom(njc) above */

	for (ssize_t i = 0; i < njc.iface_own().size(); i++) {
		nsj->ifaces.push_back(njc.iface_own(i));
	}

	if (njc.has_exec_bin()) {
		if (njc.exec_bin().has_path()) {
			nsj->argv.push_back(njc.exec_bin().path());
		}
		for (ssize_t i = 0; i < njc.exec_bin().arg().size(); i++) {
			nsj->argv.push_back(njc.exec_bin().arg(i));
		}
		if (njc.exec_bin().has_arg0()) {
			nsj->argv[0] = njc.exec_bin().arg0();
		}
		nsj->exec_fd = njc.exec_bin().exec_fd();
	}

	return true;
}

#if defined(GOOGLE_PROTOBUF_VERSION) && GOOGLE_PROTOBUF_VERSION < 4000000
#define NSJAIL_HAS_PROTOBUF_LOG_HANDLER 1
#else
#define NSJAIL_HAS_PROTOBUF_LOG_HANDLER 0
#endif

static std::list<std::string> error_messages;

#if NSJAIL_HAS_PROTOBUF_LOG_HANDLER
static void logHandler(
    google::protobuf::LogLevel level, const char* filename, int line, const std::string& message) {
	error_messages.push_back(message);
}
#endif /* NSJAIL_HAS_PROTOBUF_LOG_HANDLER */

static void flushLog() {
	for (auto message : error_messages) {
		LOG_W("ProtoTextFormat: %s", message.c_str());
	}
	error_messages.clear();
}

bool parseFile(nsj_t* nsj, const char* file) {
	LOG_D("Parsing configuration from %s", QC(file));

	std::string conf;
	if (!util::readFromFileToStr(file, &conf)) {
		LOG_E("Couldn't read config file %s", QC(file));
		return false;
	}
	if (conf.empty()) {
		LOG_E("Config file %s is empty", QC(file));
		return false;
	}

	/* Use static so we can get c_str() pointers, and copy them into the nsjconf struct */
	static nsjail::NsJailConfig json_nsc;
	static nsjail::NsJailConfig text_nsc;

#if NSJAIL_HAS_PROTOBUF_LOG_HANDLER
	google::protobuf::SetLogHandler(logHandler);
#endif /* NSJAIL_HAS_PROTOBUF_LOG_HANDLER */
	auto json_status = google::protobuf::util::JsonStringToMessage(conf, &json_nsc);
	bool text_parsed = google::protobuf::TextFormat::ParseFromString(conf, &text_nsc);

	if (json_status.ok() && text_parsed) {
		LOG_W("Config file %s ambiguously parsed as TextProto and ProtoJSON", QC(file));
		return false;
	}

	if (!json_status.ok() && !text_parsed) {
		LOG_E("Config file %s failed to parse as either TextProto or ProtoJSON", QC(file));
		flushLog();
		LOG_W("ProtoJSON parse status: '%s'", json_status.ToString().c_str());
		return false;
	}

	if (json_status.ok() && !text_parsed) {
		if (!parseInternal(nsj, json_nsc)) {
			LOG_W("Couldn't parse the ProtoJSON from %s", QC(file));
			return false;
		}
		LOG_D(
		    "Parsed JSON config from %s:\n'%s'", QC(file), json_nsc.DebugString().c_str());
		return true;
	}

	if (text_parsed && !json_status.ok()) {
		if (!parseInternal(nsj, text_nsc)) {
			LOG_W("Couldn't parse the TextProto from %s", QC(file));
			return false;
		}
		LOG_D("Parsed TextProto config from %s:\n'%s'", QC(file),
		    text_nsc.DebugString().c_str());
		return true;
	}
	return false;
}

}  // namespace config
