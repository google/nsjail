#ifndef NSJAIL_UNOTIFY_H
#define NSJAIL_UNOTIFY_H

#include "nsjail.h"

namespace unotify {

bool start(nsj_t* nsj, int unotif_fd);
void stop(nsj_t* nsj);
/* Note: printStats is in unotify/stats.h, exposed to nsjail.cc */

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_H */
