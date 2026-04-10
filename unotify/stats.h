#ifndef NSJAIL_UNOTIFY_STATS_H
#define NSJAIL_UNOTIFY_STATS_H

#include <string>

#include "nsjail.h"
#include "unotify/unotify.pb.h"

namespace unotify {

struct FsStatParams {
	std::string path;
	Stat_Path_Type jail_type = Stat_Path_Type_NONEXISTENT;
	Stat_Path_Type main_type = Stat_Path_Type_NONEXISTENT;
	Stat_Path_Mode mode = Stat_Path_Mode_UNSPECIFIED;
	std::string mode_extra;
};

struct NetStatParams {
	Stat_NetResource_Type type = Stat_NetResource_Type_UNKNOWN;
	std::string endpoint;
	bool has_port = false;
	uint32_t port = 0;
	bool has_path = false;
	FsStatParams path;
};

void addFsStat(const FsStatParams& fs, const std::string& sys_name, const std::string& args_str);
void addNetStat(const NetStatParams& net, const std::string& sys_name, const std::string& args_str);

void printStats(nsj_t* nsj);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_STATS_H */
