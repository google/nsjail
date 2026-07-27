#ifndef NSJAIL_UNOTIFY_STATS_H
#define NSJAIL_UNOTIFY_STATS_H

#include <cstddef>
#include <cstdint>
#include <map>

#include "nsjail.h"
#include "unotify/record.h"

namespace unotify {

namespace internal {
uint64_t saturatingAdd(uint64_t lhs, uint64_t rhs);
}  // namespace internal

class StatsStore {
       public:
	StatsStore(size_t max_entries, size_t max_bytes);

	bool add(const SyscallRecord& rec);
	size_t size() const;
	size_t bytes() const;
	uint64_t dropped() const;
	uint64_t count(const SyscallRecord& rec) const;
	const std::map<SyscallRecord, uint64_t>& entries() const;
	bool hasOutput() const;

       private:
	size_t max_entries_;
	size_t max_bytes_;
	size_t bytes_ = 0;
	uint64_t dropped_ = 0;
	std::map<SyscallRecord, uint64_t> entries_;
};

void addStat(const SyscallRecord& rec);
void printStats(nsj_t* nsj);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_STATS_H */
