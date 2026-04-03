#ifndef NSJAIL_UNOTIFY_RECORD_H
#define NSJAIL_UNOTIFY_RECORD_H

#include <string>
#include <tuple>
#include <vector>

#include "unotify/unotify.pb.h"

namespace unotify {

struct PathInfoRecord {
	std::string path;
	Stat_Path_Type jail_type = Stat_Path_Type_NONEXISTENT;
	Stat_Path_Type main_type = Stat_Path_Type_NONEXISTENT;
	Stat_Path_Mode mode = Stat_Path_Mode_UNSPECIFIED;
	std::string mode_extra;

	/* Lexicographical comparison to support std::map usage in stats.cc */
	bool operator<(const PathInfoRecord& o) const {
		return std::tie(path, jail_type, main_type, mode, mode_extra) <
		       std::tie(o.path, o.jail_type, o.main_type, o.mode, o.mode_extra);
	}
};

struct ResourceRecord {
	bool has_path1 = false;
	PathInfoRecord path1;

	bool has_path2 = false;
	PathInfoRecord path2;

	bool has_net = false;
	Stat_NetResource_Type net_type = Stat_NetResource_Type_UNKNOWN;
	std::string net_endpoint;
	bool has_net_port = false;
	uint32_t net_port = 0;
	bool has_net_path = false;
	PathInfoRecord net_path;

	/* Lexicographical comparison to support std::map usage in stats.cc */
	bool operator<(const ResourceRecord& o) const {
		return std::tie(has_path1, path1, has_path2, path2, has_net, net_type, net_endpoint, has_net_port, net_port, has_net_path, net_path) <
		       std::tie(o.has_path1, o.path1, o.has_path2, o.path2, o.has_net, o.net_type, o.net_endpoint, o.has_net_port, o.net_port, o.has_net_path, o.net_path);
	}
};

struct SyscallRecord {
	std::string name;
	std::vector<std::string> args;
	ResourceRecord res;

	/* Lexicographical comparison to support std::map usage in stats.cc */
	bool operator<(const SyscallRecord& other) const {
		return std::tie(name, args, res) <
		       std::tie(other.name, other.args, other.res);
	}
};

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_RECORD_H */
