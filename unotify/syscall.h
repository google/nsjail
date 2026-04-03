#ifndef NSJAIL_UNOTIFY_SYSCALL_H
#define NSJAIL_UNOTIFY_SYSCALL_H

#include <linux/seccomp.h>

#include "unotify/record.h"

namespace unotify {

void parseSyscall(struct seccomp_notif* req, SyscallRecord* rec);

}  // namespace unotify

#endif /* NSJAIL_UNOTIFY_SYSCALL_H */
