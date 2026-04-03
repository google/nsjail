#include "unotify/stats.h"

#include <fcntl.h>
#include <google/protobuf/text_format.h>
#include <unistd.h>

#include <map>
#include <mutex>

#include "logs.h"
#include "util.h"

namespace unotify {

static std::mutex stats_mu;
/* Aggregates syscall statistics on the fly.
 * Uses std::map which requires SyscallRecord to have operator<. */
static std::map<SyscallRecord, size_t> stats;

void addStat(const SyscallRecord& rec) {
	std::lock_guard<std::mutex> lock(stats_mu);
	stats[rec]++;
}

static void fillPathInfoPb(Stat_Path* pb, const PathInfoRecord& rec) {
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

struct NetInfoRecord {
	Stat_NetResource_Type type = Stat_NetResource_Type_UNKNOWN;
	std::string endpoint;
	bool has_port = false;
	uint32_t port = 0;
	bool has_path = false;
	PathInfoRecord path;

	bool operator<(const NetInfoRecord& o) const {
		if (type != o.type) return type < o.type;
		if (endpoint != o.endpoint) return endpoint < o.endpoint;
		if (has_port != o.has_port) return has_port < o.has_port;
		if (has_port) {
			if (port != o.port) return port < o.port;
		}
		if (has_path != o.has_path) return has_path < o.has_path;
		if (has_path) {
			if (path < o.path) return true;
			if (o.path < path) return false;
		}
		return false;
	}
};

struct SyscallKey {
	std::string name;
	std::vector<std::string> args;
	bool operator<(const SyscallKey& o) const {
		if (name != o.name) return name < o.name;
		return args < o.args;
	}
};

struct FsStats {
	uint64_t count = 0;
	std::map<SyscallKey, uint64_t> syscalls;
};

struct NetStats {
	uint64_t count = 0;
	std::map<SyscallKey, uint64_t> syscalls;
};

void printStats(nsj_t* nsj) {
	if (!nsj->njc.seccomp_unotify()) {
		return;
	}
	if (stats.empty()) {
		return;	 // Do not emit if empty
	}

	std::map<PathInfoRecord, FsStats> fs_stats;
	std::map<NetInfoRecord, NetStats> net_stats;

	{
		std::lock_guard<std::mutex> lock(stats_mu);
		for (const auto& [rec, count] : stats) {
			SyscallKey sys_key{rec.name, rec.args};

			if (rec.res.has_path1) {
				SyscallKey p1_key = sys_key;
				if (!rec.res.path1.mode_extra.empty()) {
					p1_key.args.push_back(
					    "mode_extra=" + rec.res.path1.mode_extra);
				}
				fs_stats[rec.res.path1].count += count;
				fs_stats[rec.res.path1].syscalls[p1_key] += count;
			}
			if (rec.res.has_path2) {
				SyscallKey p2_key = sys_key;
				if (!rec.res.path2.mode_extra.empty()) {
					p2_key.args.push_back(
					    "mode_extra=" + rec.res.path2.mode_extra);
				}
				fs_stats[rec.res.path2].count += count;
				fs_stats[rec.res.path2].syscalls[p2_key] += count;
			}
			if (rec.res.has_net) {
				NetInfoRecord net_rec;
				net_rec.type = rec.res.net_type;
				net_rec.endpoint = rec.res.net_endpoint;
				net_rec.has_port = rec.res.has_net_port;
				net_rec.port = rec.res.net_port;
				net_rec.has_path = rec.res.has_net_path;
				net_rec.path = rec.res.net_path;

				net_stats[net_rec].count += count;
				net_stats[net_rec].syscalls[sys_key] += count;
			}
		}
	}

	Stat report_pb;

	for (const auto& [path_rec, fs_stat] : fs_stats) {
		Stat_Path* fs_pb = report_pb.add_fs_access();
		fs_pb->set_count(fs_stat.count);
		fillPathInfoPb(fs_pb, path_rec);

		for (const auto& [sys_key, sys_count] : fs_stat.syscalls) {
			Stat_Syscall* sys_pb = fs_pb->add_syscall();
			sys_pb->set_name(sys_key.name);
			sys_pb->set_count(sys_count);
			for (const auto& arg : sys_key.args) {
				sys_pb->add_args(arg);
			}
		}
	}

	for (const auto& [net_rec, net_stat] : net_stats) {
		Stat_NetResource* net_pb = report_pb.add_net_access();
		net_pb->set_count(net_stat.count);

		net_pb->set_type(net_rec.type);
		if (!net_rec.endpoint.empty()) {
			net_pb->set_endpoint(net_rec.endpoint);
		}
		if (net_rec.has_port) {
			net_pb->set_port(net_rec.port);
		}
		if (net_rec.has_path) {
			fillPathInfoPb(net_pb->mutable_socket_path(), net_rec.path);
		}

		for (const auto& [sys_key, sys_count] : net_stat.syscalls) {
			Stat_Syscall* sys_pb = net_pb->add_syscall();
			sys_pb->set_name(sys_key.name);
			sys_pb->set_count(sys_count);
			for (const auto& arg : sys_key.args) {
				sys_pb->add_args(arg);
			}
		}
	}

	std::string text_report;
	google::protobuf::TextFormat::PrintToString(report_pb, &text_report);

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
