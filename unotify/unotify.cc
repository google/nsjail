/*
 * Seccomp Unotify subsystem for nsjail.
 * -----------------------------------------
 *
 * This module allows nsjail to observe and log syscalls made by the
 * sandboxed process using the SECCOMP_USER_NOTIF feature. It registers
 * the unotify fd with the per-child epoll loop and processes
 * notifications in-line (no dedicated thread).
 *
 * Ownership: start() only takes ownership of the passed fd on success.
 * On success, the fd is managed by the event loop (freed via unotify::stop()).
 * On failure, the fd is untouched and remains the caller's responsibility to close.
 */

#include "unotify/unotify.h"

#include <fcntl.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <vector>

#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "monitor.h"
#include "unotify/stats.h"
#include "unotify/syscall.h"
#include "util.h"

namespace unotify {

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

/*
 * Checks if the target process is still alive and the notification ID is valid.
 * Returns true if valid, false otherwise.
 */
[[nodiscard]] static bool isTargetAlive(int fd, __u64 last_id) {
	return TEMP_FAILURE_RETRY(ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &last_id)) == 0;
}

/*
 * Per-fd context holding the notification fd and kernel-reported structure
 * sizes for seccomp_notif / seccomp_notif_resp.
 */
struct unotifyCtx_t {
	int fd = -1;
	int pidfd = -1;
	std::vector<uint8_t> req_buf;
	std::vector<uint8_t> resp_buf;
};

static thread_local unotifyCtx_t current_ctx;

static void closeAndUnregister(int fd) {
	if (fd >= 0) {
		(void)monitor::removeFd(fd);
		close(fd);
		current_ctx.fd = -1;
	}
}

void stop() {
	closeAndUnregister(current_ctx.fd);
	current_ctx.req_buf.clear();
	current_ctx.resp_buf.clear();
}

/*
 * Epoll callback that processes pending seccomp notifications from the
 * kernel. For each notification, it records statistics and sends a CONTINUE
 * response so the traced syscall proceeds in the child.
 *
 * We process one notification per callback to avoid event starvation,
 * yielding control back to the event loop.
 */
static void unotifyCb(int fd, uint32_t events, void* /* data */) {
	if (events & (EPOLLHUP | EPOLLERR)) {
		LOG_D("unotif_fd=%d hung up or error, removing from epoll", fd);
		closeAndUnregister(fd);
		return;
	}

	struct seccomp_notif* req =
	    reinterpret_cast<struct seccomp_notif*>(current_ctx.req_buf.data());
	struct seccomp_notif_resp* resp =
	    reinterpret_cast<struct seccomp_notif_resp*>(current_ctx.resp_buf.data());

	memset(req, 0, current_ctx.req_buf.size());
	if (TEMP_FAILURE_RETRY(ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req)) == -1) {
		/* EAGAIN/EWOULDBLOCK = no more pending */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		if (errno == ENOENT) {
			LOG_D("unotif_fd=%d returned ENOENT, child likely gone. Removing "
			      "from epoll.",
			    fd);
			closeAndUnregister(fd);
			return;
		}
		PLOG_W("SECCOMP_IOCTL_NOTIF_RECV failed unexpectedly");
		closeAndUnregister(fd);
		return;
	}

	LOG_D("unotifyCb: before parseSyscall, nr=%d", req->data.nr);
	parseSyscall(req, current_ctx.pidfd);
	LOG_D("unotifyCb: after parseSyscall");

	if (!isTargetAlive(fd, req->id)) {
		return;
	}

	memset(resp, 0, current_ctx.resp_buf.size());
	resp->id = req->id;

	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	if (TEMP_FAILURE_RETRY(ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp)) == -1) {
		if (errno != ENOENT) {
			PLOG_W("SECCOMP_IOCTL_NOTIF_SEND");
		}
	}
}

/*
 * Initializes the unotify monitoring for one child process.
 *
 * Queries SECCOMP_GET_NOTIF_SIZES from the kernel to learn the correct
 * allocation sizes, sets the fd non-blocking, and registers it with the
 * epoll loop.
 *
 * Returns true if the fd was successfully absorbed by the loop. On failure,
 * the fd is untouched and remains the caller's responsibility to close.
 */
[[nodiscard]] bool start(nsj_t* nsj, int fd, int pidfd) {
	if (current_ctx.fd != -1) {
		LOG_W("unotify::start called on already initialized context");
		return false;
	}
	thread_local struct seccomp_notif_sizes sizes = {0, 0, 0};
	if (sizes.seccomp_notif == 0) {
		if (util::syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, (uintptr_t)&sizes) ==
		    -1) {
			PLOG_W("seccomp(SECCOMP_GET_NOTIF_SIZES)");
			return false;
		}
	}

	current_ctx.fd = fd;
	current_ctx.pidfd = pidfd;

	current_ctx.req_buf.resize(sizes.seccomp_notif);
	current_ctx.resp_buf.resize(sizes.seccomp_notif_resp);
	bool success = false;
	defer {
		if (!success) {
			current_ctx.req_buf.clear();
			current_ctx.resp_buf.clear();
			current_ctx.fd = -1;
		}
	};

	if (!util::setNonBlock(fd)) {
		return false;
	}

	if (!monitor::addFd(fd, EPOLLIN, unotifyCb, nullptr)) {
		PLOG_W("monitor::addFd for unotify failed");
		return false;
	}

	success = true;
	return true;
}

}  // namespace unotify
