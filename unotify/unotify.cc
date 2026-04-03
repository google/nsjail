/*
 * Seccomp Unotify subsystem for nsjail.
 * This module allows nsjail to observe and log syscalls made by the sandboxed
 * process using the SECCOMP_USER_NOTIF feature. It runs a background thread
 * that reads notifications, decodes arguments, and aggregates statistics.
 */

#include "unotify.h"

#include <linux/seccomp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <thread>

#include "logs.h"
#include "unotify/record.h"
#include "unotify/stats.h"
#include "unotify/syscall.h"
#include "util.h"

namespace unotify {

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOWR(2, __u64)
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

static int unotif_fd = -1;
static std::thread* worker_thread = nullptr;

static bool isTargetAlive(int fd, __u64 last_id) {
	return ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &last_id) == 0;
}

static void threadMain() {
	LOG_I("Started unotify loop");
	/*
	 * When last_id is 0 (no notification received yet), NOTIF_ID_VALID
	 * will always fail since ID 0 is never valid. This correctly exits
	 * the loop when NOTIF_RECV has never succeeded (child died before
	 * making any traced syscall).
	 */
	__u64 last_id = 0;

	while (true) {
		struct pollfd pfd = {.fd = unotif_fd, .events = POLLIN, .revents = 0};

		int ret = poll(&pfd, 1, -1);
		if (ret == -1) {
			if (errno == EINTR) continue;
			PLOG_E("poll failed");
			if (!isTargetAlive(unotif_fd, last_id)) break;
			continue;
		}

		struct seccomp_notif req = {};
		if (ioctl(unotif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) == -1) {
			if (errno == EINTR) continue;
			PLOG_D("SECCOMP_IOCTL_NOTIF_RECV");
			if (!isTargetAlive(unotif_fd, last_id)) break;
			continue;
		}
		last_id = req.id;

		LOG_D("Received seccomp notification for syscall %d", req.data.nr);

		SyscallRecord rec;
		parseSyscall(&req, &rec);
		addStat(rec);

		if (!isTargetAlive(unotif_fd, req.id)) {
			break;
		}

		struct seccomp_notif_resp resp = {};
		resp.id = req.id;
		resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

		if (ioctl(unotif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == -1) {
			if (errno != ENOENT) {
				PLOG_E("SECCOMP_IOCTL_NOTIF_SEND failed");
			}
			if (!isTargetAlive(unotif_fd, req.id)) break;
		}
	}
}

bool start(nsj_t* nsj, int fd) {
	if (worker_thread) {
		LOG_W("unotify::start() called while already running. "
		      "Concurrent tracing in LISTEN mode is not yet supported. "
		      "Closing notification fd for this process.");
		close(fd);
		return true;
	}
	unotif_fd = fd;
	worker_thread = new std::thread(threadMain);
	return true;
}

/*
 * Called after killAndReapAll(). The worker thread exits its loop when
 * isTargetAlive() (SECCOMP_IOCTL_NOTIF_ID_VALID) reports the target is dead.
 */
void stop(nsj_t* nsj) {
	if (worker_thread) {
		worker_thread->join();
		delete worker_thread;
		worker_thread = nullptr;
	}
	if (unotif_fd != -1) {
		close(unotif_fd);
		unotif_fd = -1;
	}
	printStats(nsj);
}

}  // namespace unotify
