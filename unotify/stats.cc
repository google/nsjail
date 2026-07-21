#include "unotify/stats.h"

#include <fcntl.h>
#include <google/protobuf/text_format.h>
#include <inttypes.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <mutex>

#include "logs.h"
#include "util.h"

namespace unotify {

namespace {
/* Bound attacker-controlled telemetry retained by the privileged supervisor.
 * The entry cap also bounds std::map/vector/object overhead not counted by the
 * string-payload budget. */
constexpr size_t kMaxStatsEntries = 4096;
constexpr size_t kMaxStatsBytes = 16 * 1024 * 1024;
/* execveat has the largest producer-generated args vector: one dirfd plus the
 * kMaxArgs (128) entries from each of argv and envp. */
constexpr size_t kMaxStatsArgs = 257;

struct SizeResult {
	bool success;
	size_t value;
};

SizeResult addBytes(size_t lhs, size_t rhs) {
	if (rhs > std::numeric_limits<size_t>::max() - lhs) {
		return {false, 0};
	}
	return {true, lhs + rhs};
}

SizeResult multiplyBytes(size_t lhs, size_t rhs) {
	if (lhs != 0 && rhs > std::numeric_limits<size_t>::max() / lhs) {
		return {false, 0};
	}
	return {true, lhs * rhs};
}

SizeResult recordBytes(const SyscallRecord& rec) {
	size_t bytes = 0;
	auto result = addBytes(bytes, rec.name.size());
	if (!result.success) {
		return result;
	}
	bytes = result.value;
	result = multiplyBytes(rec.args.size(), sizeof(std::string));
	if (!result.success) {
		return result;
	}
	result = addBytes(bytes, result.value);
	if (!result.success) {
		return result;
	}
	bytes = result.value;
	for (const auto& arg : rec.args) {
		result = addBytes(bytes, arg.size());
		if (!result.success) {
			return result;
		}
		bytes = result.value;
	}
	const std::string* resource_strings[] = {
	    &rec.res.path1.path,
	    &rec.res.path1.mode_extra,
	    &rec.res.path2.path,
	    &rec.res.path2.mode_extra,
	    &rec.res.net_endpoint,
	    &rec.res.net_path.path,
	    &rec.res.net_path.mode_extra,
	};
	for (const std::string* str : resource_strings) {
		result = addBytes(bytes, str->size());
		if (!result.success) {
			return result;
		}
		bytes = result.value;
	}
	return {true, bytes};
}
}  // namespace

namespace internal {

uint64_t saturatingAdd(uint64_t lhs, uint64_t rhs) {
	if (rhs > std::numeric_limits<uint64_t>::max() - lhs) {
		return std::numeric_limits<uint64_t>::max();
	}
	return lhs + rhs;
}

}  // namespace internal

static std::mutex stats_mu;
static StatsStore stats(kMaxStatsEntries, kMaxStatsBytes);

StatsStore::StatsStore(size_t max_entries, size_t max_bytes)
    : max_entries_(max_entries), max_bytes_(max_bytes) {
}

bool StatsStore::add(const SyscallRecord& rec) {
	if (rec.args.size() > kMaxStatsArgs) {
		dropped_ = internal::saturatingAdd(dropped_, 1);
		return false;
	}
	auto it = entries_.find(rec);
	if (it != entries_.end()) {
		it->second = internal::saturatingAdd(it->second, 1);
		return true;
	}
	if (entries_.size() >= max_entries_) {
		dropped_ = internal::saturatingAdd(dropped_, 1);
		return false;
	}
	const SizeResult rec_bytes = recordBytes(rec);
	if (!rec_bytes.success || bytes_ > max_bytes_ || rec_bytes.value > max_bytes_ - bytes_) {
		dropped_ = internal::saturatingAdd(dropped_, 1);
		return false;
	}
	entries_.emplace(rec, 1);
	bytes_ += rec_bytes.value;
	return true;
}

size_t StatsStore::size() const {
	return entries_.size();
}

size_t StatsStore::bytes() const {
	return bytes_;
}

uint64_t StatsStore::dropped() const {
	return dropped_;
}

uint64_t StatsStore::count(const SyscallRecord& rec) const {
	auto it = entries_.find(rec);
	return it == entries_.end() ? 0 : it->second;
}

const std::map<SyscallRecord, uint64_t>& StatsStore::entries() const {
	return entries_;
}

bool StatsStore::hasOutput() const {
	return !entries_.empty() || dropped_ != 0;
}

void addStat(const SyscallRecord& rec) {
	std::lock_guard<std::mutex> lock(stats_mu);
	stats.add(rec);
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

	std::map<PathInfoRecord, FsStats> fs_stats;
	std::map<NetInfoRecord, NetStats> net_stats;
	uint64_t dropped = 0;
	bool has_entries = false;

	{
		std::lock_guard<std::mutex> lock(stats_mu);
		if (!stats.hasOutput()) {
			return;	 // Do not emit if empty
		}
		has_entries = stats.size() != 0;
		for (const auto& [rec, count] : stats.entries()) {
			SyscallKey sys_key{rec.name, rec.args};

			if (rec.res.has_path1) {
				SyscallKey p1_key = sys_key;
				if (!rec.res.path1.mode_extra.empty()) {
					p1_key.args.push_back(
					    "mode_extra=" + rec.res.path1.mode_extra);
				}
				FsStats& path_stats = fs_stats[rec.res.path1];
				path_stats.count = internal::saturatingAdd(path_stats.count, count);
				path_stats.syscalls[p1_key] =
				    internal::saturatingAdd(path_stats.syscalls[p1_key], count);
			}
			if (rec.res.has_path2) {
				SyscallKey p2_key = sys_key;
				if (!rec.res.path2.mode_extra.empty()) {
					p2_key.args.push_back(
					    "mode_extra=" + rec.res.path2.mode_extra);
				}
				FsStats& path_stats = fs_stats[rec.res.path2];
				path_stats.count = internal::saturatingAdd(path_stats.count, count);
				path_stats.syscalls[p2_key] =
				    internal::saturatingAdd(path_stats.syscalls[p2_key], count);
			}
			if (rec.res.has_net) {
				NetInfoRecord net_rec;
				net_rec.type = rec.res.net_type;
				net_rec.endpoint = rec.res.net_endpoint;
				net_rec.has_port = rec.res.has_net_port;
				net_rec.port = rec.res.net_port;
				net_rec.has_path = rec.res.has_net_path;
				net_rec.path = rec.res.net_path;

				NetStats& resource_stats = net_stats[net_rec];
				resource_stats.count =
				    internal::saturatingAdd(resource_stats.count, count);
				resource_stats.syscalls[sys_key] = internal::saturatingAdd(
				    resource_stats.syscalls[sys_key], count);
			}
		}
		dropped = stats.dropped();
	}
	if (dropped != 0) {
		LOG_W("Dropped %" PRIu64
		      " seccomp-unotify records after reaching statistics limits",
		    dropped);
	}
	if (!has_entries) {
		return;
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
	if (!google::protobuf::TextFormat::PrintToString(report_pb, &text_report)) {
		LOG_W("Failed to format unotify report");
		return;
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
