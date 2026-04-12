#ifndef NSJAIL_UNOTIFY_H
#define NSJAIL_UNOTIFY_H

#include "nsjail.h"

namespace unotify {

[[nodiscard]] bool start(nsj_t* nsj, int unotif_fd, int pidfd = -1);
void stop(void);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_H */
