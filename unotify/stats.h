#ifndef NSJAIL_UNOTIFY_STATS_H
#define NSJAIL_UNOTIFY_STATS_H

#include "nsjail.h"
#include "unotify/record.h"

namespace unotify {

void addStat(const SyscallRecord& rec);
void printStats(nsj_t* nsj);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_STATS_H */
