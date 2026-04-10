#include "unotify/stats.h"

#include <fcntl.h>
#include <google/protobuf/text_format.h>
#include <unistd.h>

#include <mutex>

#include "logs.h"
#include "util.h"

namespace unotify {

static std::mutex stats_mu;

struct StatEntry {
	SyscallRecord rec;
	size_t count;
};

constexpr size_t MAX_STATS = 1024;
static StatEntry stats_array[MAX_STATS];
static size_t stats_count = 0;

void addStat(const SyscallRecord& rec) {
	std::lock_guard<std::mutex> lock(stats_mu);
	for (size_t i = 0; i < stats_count; ++i) {
		if (!(stats_array[i].rec < rec) && !(rec < stats_array[i].rec)) {
			stats_array[i].count++;
			return;
		}
	}
	if (stats_count < MAX_STATS) {
		stats_array[stats_count].rec = rec;
		stats_array[stats_count].count = 1;
		stats_count++;
	} else {
		LOG_W("Max stats reached, dropping record");
	}
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
	std::string args_str;
	bool operator<(const SyscallKey& o) const {
		if (name != o.name) return name < o.name;
		return args_str < o.args_str;
	}
};

constexpr size_t MAX_SYSCALLS_PER_RESOURCE = 64;

struct SyscallKeyEntry {
	SyscallKey key;
	uint64_t count;
};

struct FsStats {
	uint64_t count = 0;
	SyscallKeyEntry syscalls[MAX_SYSCALLS_PER_RESOURCE];
	size_t syscalls_count = 0;
};

struct NetStats {
	uint64_t count = 0;
	SyscallKeyEntry syscalls[MAX_SYSCALLS_PER_RESOURCE];
	size_t syscalls_count = 0;
};

struct FsStatsEntry {
	PathInfoRecord path_rec;
	FsStats stats;
};

struct NetStatsEntry {
	NetInfoRecord net_rec;
	NetStats stats;
};

constexpr size_t MAX_FS_STATS = 256;
constexpr size_t MAX_NET_STATS = 256;

static FsStats* find_or_insert_fs(FsStatsEntry* array, size_t* count, const PathInfoRecord& key) {
	for (size_t i = 0; i < *count; ++i) {
		if (!(array[i].path_rec < key) && !(key < array[i].path_rec)) {
			return &array[i].stats;
		}
	}
	if (*count < MAX_FS_STATS) {
		array[*count].path_rec = key;
		FsStats* stats = &array[*count].stats;
		stats->count = 0;
		stats->syscalls_count = 0;
		(*count)++;
		return stats;
	}
	return nullptr;
}

static NetStats* find_or_insert_net(NetStatsEntry* array, size_t* count, const NetInfoRecord& key) {
	for (size_t i = 0; i < *count; ++i) {
		if (!(array[i].net_rec < key) && !(key < array[i].net_rec)) {
			return &array[i].stats;
		}
	}
	if (*count < MAX_NET_STATS) {
		array[*count].net_rec = key;
		NetStats* stats = &array[*count].stats;
		stats->count = 0;
		stats->syscalls_count = 0;
		(*count)++;
		return stats;
	}
	return nullptr;
}

static SyscallKeyEntry* find_or_insert_syscall(
    SyscallKeyEntry* array, size_t* count, const SyscallKey& key) {
	for (size_t i = 0; i < *count; ++i) {
		if (!(array[i].key < key) && !(key < array[i].key)) {
			return &array[i];
		}
	}
	if (*count < MAX_SYSCALLS_PER_RESOURCE) {
		array[*count].key = key;
		array[*count].count = 0;
		SyscallKeyEntry* entry = &array[*count];
		(*count)++;
		return entry;
	}
	return nullptr;
}

void printStats(nsj_t* nsj) {
	if (!nsj->njc.seccomp_unotify()) {
		return;
	}

	static thread_local FsStatsEntry fs_stats_array[MAX_FS_STATS];
	size_t fs_stats_count = 0;

	static thread_local NetStatsEntry net_stats_array[MAX_NET_STATS];
	size_t net_stats_count = 0;

	{
		std::lock_guard<std::mutex> lock(stats_mu);
		if (stats_count == 0) {
			return;	 // Do not emit if empty
		}
		for (size_t i = 0; i < stats_count; ++i) {
			const auto& rec = stats_array[i].rec;
			size_t count = stats_array[i].count;
			SyscallKey sys_key{rec.name, rec.args_str};

			if (rec.res.has_path1) {
				SyscallKey p1_key = sys_key;
				if (!rec.res.path1.mode_extra.empty()) {
					p1_key.args_str +=
					    "mode_extra=" + rec.res.path1.mode_extra + " ";
				}
				FsStats* fs_stat = find_or_insert_fs(
				    fs_stats_array, &fs_stats_count, rec.res.path1);
				if (fs_stat) {
					fs_stat->count += count;
					SyscallKeyEntry* sys_entry = find_or_insert_syscall(
					    fs_stat->syscalls, &fs_stat->syscalls_count, p1_key);
					if (sys_entry) {
						sys_entry->count += count;
					}
				}
			}
			if (rec.res.has_path2) {
				SyscallKey p2_key = sys_key;
				if (!rec.res.path2.mode_extra.empty()) {
					p2_key.args_str +=
					    "mode_extra=" + rec.res.path2.mode_extra + " ";
				}
				FsStats* fs_stat = find_or_insert_fs(
				    fs_stats_array, &fs_stats_count, rec.res.path2);
				if (fs_stat) {
					fs_stat->count += count;
					SyscallKeyEntry* sys_entry = find_or_insert_syscall(
					    fs_stat->syscalls, &fs_stat->syscalls_count, p2_key);
					if (sys_entry) {
						sys_entry->count += count;
					}
				}
			}
			if (rec.res.has_net) {
				NetInfoRecord net_rec;
				net_rec.type = rec.res.net_type;
				net_rec.endpoint = rec.res.net_endpoint;
				net_rec.has_port = rec.res.has_net_port;
				net_rec.port = rec.res.net_port;
				net_rec.has_path = rec.res.has_net_path;
				net_rec.path = rec.res.net_path;

				NetStats* net_stat =
				    find_or_insert_net(net_stats_array, &net_stats_count, net_rec);
				if (net_stat) {
					net_stat->count += count;
					SyscallKeyEntry* sys_entry = find_or_insert_syscall(
					    net_stat->syscalls, &net_stat->syscalls_count, sys_key);
					if (sys_entry) {
						sys_entry->count += count;
					}
				}
			}
		}
	}

	Stat report_pb;

	for (size_t i = 0; i < fs_stats_count; ++i) {
		const auto& path_rec = fs_stats_array[i].path_rec;
		const auto& fs_stat = fs_stats_array[i].stats;
		Stat_Path* fs_pb = report_pb.add_fs_access();
		fs_pb->set_count(fs_stat.count);
		fillPathInfoPb(fs_pb, path_rec);

		for (size_t j = 0; j < fs_stat.syscalls_count; ++j) {
			Stat_Syscall* sys_pb = fs_pb->add_syscall();
			sys_pb->set_name(fs_stat.syscalls[j].key.name);
			sys_pb->set_count(fs_stat.syscalls[j].count);
			sys_pb->add_args(fs_stat.syscalls[j].key.args_str);
		}
	}

	for (size_t i = 0; i < net_stats_count; ++i) {
		const auto& net_rec = net_stats_array[i].net_rec;
		const auto& net_stat = net_stats_array[i].stats;
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

		for (size_t j = 0; j < net_stat.syscalls_count; ++j) {
			Stat_Syscall* sys_pb = net_pb->add_syscall();
			sys_pb->set_name(net_stat.syscalls[j].key.name);
			sys_pb->set_count(net_stat.syscalls[j].count);
			sys_pb->add_args(net_stat.syscalls[j].key.args_str);
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
