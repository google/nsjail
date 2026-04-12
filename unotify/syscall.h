#ifndef NSJAIL_UNOTIFY_SYSCALL_H
#define NSJAIL_UNOTIFY_SYSCALL_H

#include <linux/seccomp.h>

namespace unotify {

void parseSyscall(struct seccomp_notif* req, int pidfd = -1);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_SYSCALL_H */
