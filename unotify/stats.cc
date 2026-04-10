#include "unotify/stats.h"
#include "unotify/stats_internal.h"

#include <fcntl.h>
#include <google/protobuf/text_format.h>
#include <unistd.h>

#include <mutex>

#include "logs.h"
#include "util.h"

namespace unotify {

static std::mutex stats_mu;
static Stat global_report_pb;

static void fillPathInfoPb(Stat_Path* pb, const FsStatParams& rec) {
	pb->set_path(rec.path);
	pb->set_jail_type(rec.jail_type);
	pb->set_main_type(rec.main_type);
	pb->set_exists_in_jail(
	    rec.jail_type != Stat_Path_Type_NONEXISTENT && rec.jail_type != Stat_Path_Type_UNKNOWN);
	pb->set_exists_in_main(
	    rec.main_type != Stat_Path_Type_NONEXISTENT && rec.main_type != Stat_Path_Type_UNKNOWN);
	if (rec.mode != Stat_Path_Mode_UNSPECIFIED) {
		pb->set_mode(rec.mode);
	}
}

static Stat_Syscall* getOrAddSyscall(google::protobuf::RepeatedPtrField<Stat_Syscall>* syscalls,
    const std::string& sys_name, const std::string& args_str) {
	for (int i = 0; i < syscalls->size(); ++i) {
		Stat_Syscall* sys_pb = syscalls->Mutable(i);
		if (sys_pb->name() != sys_name) {
			continue;
		}
		/* Compare stored args (0 or 1 entry) against the incoming string */
		std::string stored = sys_pb->args_size() > 0 ? sys_pb->args(0) : "";
		if (stored == args_str) {
			return sys_pb;
		}
	}
	/* Not found, add new */
	Stat_Syscall* sys_pb = syscalls->Add();
	sys_pb->set_name(sys_name);
	sys_pb->set_count(0);
	if (!args_str.empty()) {
		sys_pb->add_args(args_str);
	}
	return sys_pb;
}

void addFsStat(const FsStatParams& fs, const std::string& sys_name, const std::string& args_str) {
	std::lock_guard<std::mutex> lock(stats_mu);
	bool found = false;
	Stat_Path* path_pb = nullptr;
	for (int i = 0; i < global_report_pb.fs_access_size(); ++i) {
		Stat_Path* pb = global_report_pb.mutable_fs_access(i);
		if (pb->path() == fs.path && pb->jail_type() == fs.jail_type &&
		    pb->main_type() == fs.main_type && pb->mode() == fs.mode) {
			path_pb = pb;
			found = true;
			break;
		}
	}
	if (!found) {
		path_pb = global_report_pb.add_fs_access();
		path_pb->set_count(0);
		fillPathInfoPb(path_pb, fs);
	}
	path_pb->set_count(path_pb->count() + 1);

	std::string full_args = args_str;
	if (!fs.mode_extra.empty()) {
		full_args += "mode_extra=" + fs.mode_extra + " ";
	}

	Stat_Syscall* sys_pb = getOrAddSyscall(path_pb->mutable_syscall(), sys_name, full_args);
	sys_pb->set_count(sys_pb->count() + 1);
}

void addNetStat(
    const NetStatParams& net, const std::string& sys_name, const std::string& args_str) {
	std::lock_guard<std::mutex> lock(stats_mu);
	bool found = false;
	Stat_NetResource* net_pb = nullptr;
	for (int i = 0; i < global_report_pb.net_access_size(); ++i) {
		Stat_NetResource* pb = global_report_pb.mutable_net_access(i);
		if (pb->type() == net.type && pb->endpoint() == net.endpoint &&
		    pb->has_port() == net.has_port) {
			if (net.has_port && pb->port() != net.port) continue;
			if (net.has_path) {
				if (!pb->has_socket_path() ||
				    pb->socket_path().path() != net.path.path) {
					continue;
				}
			} else if (pb->has_socket_path()) {
				continue;
			}
			net_pb = pb;
			found = true;
			break;
		}
	}
	if (!found) {
		net_pb = global_report_pb.add_net_access();
		net_pb->set_count(0);
		net_pb->set_type(net.type);
		if (!net.endpoint.empty()) {
			net_pb->set_endpoint(net.endpoint);
		}
		if (net.has_port) {
			net_pb->set_port(net.port);
		}
		if (net.has_path) {
			fillPathInfoPb(net_pb->mutable_socket_path(), net.path);
		}
	}
	net_pb->set_count(net_pb->count() + 1);

	Stat_Syscall* sys_pb = getOrAddSyscall(net_pb->mutable_syscall(), sys_name, args_str);
	sys_pb->set_count(sys_pb->count() + 1);
}

void printStats(nsj_t* nsj) {
	if (!nsj->njc.seccomp_unotify()) {
		return;
	}

	std::string text_report;
	{
		std::lock_guard<std::mutex> lock(stats_mu);
		if (global_report_pb.fs_access_size() == 0 &&
		    global_report_pb.net_access_size() == 0) {
			return;	 // Do not emit if empty
		}
		google::protobuf::TextFormat::PrintToString(global_report_pb, &text_report);
	}

	LOG_I("unotify report:\n%s", text_report.c_str());

	if (!nsj->njc.seccomp_unotify_report().empty()) {
		if (!util::writeBufToFile(nsj->njc.seccomp_unotify_report().c_str(),
			text_report.data(), text_report.size(), O_CREAT | O_WRONLY | O_TRUNC)) {
			PLOG_W("Failed to write unotify report to %s",
			    nsj->njc.seccomp_unotify_report().c_str());
		}
	}
}

}  // namespace unotify
