/*
 * nsjail - per-child monitor thread
 * -----------------------------------------
 *
 * Each sandboxed child gets a dedicated monitor thread with its own
 * epoll-based event loop.  The thread multiplexes:
 *
 *   pidfd       -- child death notification
 *   ipc_fd      -- parent↔child IPC socketpair
 *   sockproxy   -- stdin/stdout splice proxy (listen mode only)
 *   unotify     -- seccomp user notifications
 *   nstun       -- TUN-based networking
 *
 * Lifecycle:
 *   1. Receive setup FDs from child via IPC (tap, unotify, etc.)
 *   2. Acknowledge child with MSG_TAG_READY_H2J
 *   3. Enter epoll loop
 *   4. On child death (pidfd) -> cleanUpAndExit()
 *   5. On setup error         -> killAndExit()
 */

#include "monitor.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "net.h"
#include "nsjail.h"
#include "nstun/nstun.h"
#include "sockproxy/sockproxy.h"
#include "subproc.h"
#include "unotify/unotify.h"
#include "util.h"

namespace monitor {

/* --- pipe bundle for listen-mode proxy ----------------- */

struct ProxyPipes {
	int child_in = -1;
	int child_out = -1;
	int parent_in = -1;
	int parent_out = -1;
	int connfd = -1;

	void closeAll() {
		if (child_in >= 0) {
			close(child_in);
		}
		if (child_out >= 0) {
			close(child_out);
		}
		if (parent_in >= 0) {
			close(parent_in);
		}
		if (parent_out >= 0) {
			close(parent_out);
		}
		if (connfd >= 0) {
			close(connfd);
		}
		child_in = child_out = parent_in = parent_out = connfd = -1;
	}
};

/* --- epoll handler types ------------------------------- */

struct fdHandler_t {
	int fd;
	fdCb_t cb;
	void* data;
};

/* --- per-thread context -------------------------------- */

constexpr size_t MAX_EVENTS = 16;
constexpr size_t MAX_HANDLERS = 2048;
constexpr size_t MAX_PERIODICS = 16;
constexpr int kSetupTimeoutSec = 10;
constexpr int kShutdownEscalationSec = 2;
constexpr int kPollTimeoutSec = 1;
constexpr int kPeriodicIntervalMs = 1000;

struct ThreadCtx {
	/* child identity */
	nsj_t* nsj = nullptr;
	pid_t pid = -1;
	int pidfd = -1;
	int ipc_fd = -1;
	time_t start_time = 0;
	char remote_txt[128];

	/* proxy pipe FDs (listen mode only) */
	ProxyPipes pipes;

	/* epoll state */
	int epoll_fd = -1;
	fdHandler_t fd_handlers[MAX_HANDLERS];
	size_t fd_handlers_count = 0;
	periodicCb_t periodics[MAX_PERIODICS];
	size_t periodics_count = 0;
	bool stop_requested = false;

	void reset() {
		nsj = nullptr;
		pid = -1;
		pidfd = -1;
		ipc_fd = -1;
		start_time = 0;
		remote_txt[0] = '\0';
		pipes.child_in = -1;
		pipes.child_out = -1;
		pipes.parent_in = -1;
		pipes.parent_out = -1;
		pipes.connfd = -1;
		epoll_fd = -1;
		fd_handlers_count = 0;
		periodics_count = 0;
		stop_requested = false;
	}
};

static thread_local ThreadCtx current_ctx;

bool addFd(int fd, uint32_t events, fdCb_t cb, void* data) {
	if (fd < 0) {
		return false;
	}
	for (size_t i = 0; i < current_ctx.fd_handlers_count; ++i) {
		if (current_ctx.fd_handlers[i].fd == fd) {
			LOG_W("FD %d already registered in monitor", fd);
			return false;
		}
	}
	if (current_ctx.fd_handlers_count >= MAX_HANDLERS) {
		LOG_W("Too many FD handlers in monitor");
		return false;
	}
	current_ctx.fd_handlers[current_ctx.fd_handlers_count++] = {
	    .fd = fd,
	    .cb = cb,
	    .data = data,
	};
	struct epoll_event ev = {
	    .events = events,
	    .data = {
		.fd = fd,
	    },
	};
	if (epoll_ctl(current_ctx.epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		PLOG_W("epoll_ctl(EPOLL_CTL_ADD, fd=%d)", fd);
		current_ctx.fd_handlers_count--;
		return false;
	}
	return true;
}

bool removeFd(int fd) {
	if (fd < 0) {
		return false;
	}
	bool found = false;
	for (size_t i = 0; i < current_ctx.fd_handlers_count; ++i) {
		if (current_ctx.fd_handlers[i].fd == fd) {
			current_ctx.fd_handlers[i] =
			    current_ctx.fd_handlers[current_ctx.fd_handlers_count - 1];
			current_ctx.fd_handlers_count--;
			found = true;
			break;
		}
	}
	if (!found) {
		LOG_W("FD %d not found in monitor", fd);
	}
	if (epoll_ctl(current_ctx.epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
		PLOG_W("epoll_ctl(EPOLL_CTL_DEL, fd=%d)", fd);
	}
	return true;
}

bool modFd(int fd, uint32_t events) {
	if (fd < 0) {
		return false;
	}
	struct epoll_event ev = {
	    .events = events,
	    .data = {
		.fd = fd,
	    },
	};
	if (epoll_ctl(current_ctx.epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
		PLOG_W("epoll_ctl(EPOLL_CTL_MOD, fd=%d)", fd);
		return false;
	}
	return true;
}

void addPeriodic(periodicCb_t cb) {
	if (current_ctx.periodics_count >= MAX_PERIODICS) {
		LOG_W("Too many periodic callbacks in monitor");
		return;
	}
	current_ctx.periodics[current_ctx.periodics_count++] = cb;
}

void stop() {
	current_ctx.stop_requested = true;
}

static fdHandler_t* findHandler(int fd) {
	for (size_t j = 0; j < current_ctx.fd_handlers_count; ++j) {
		if (current_ctx.fd_handlers[j].fd == fd) {
			return &current_ctx.fd_handlers[j];
		}
	}
	return nullptr;
}

static void dispatchEvents(struct epoll_event* events, int nfds) {
	for (int i = 0; i < nfds; ++i) {
		int fd = events[i].data.fd;
		fdHandler_t* h = findHandler(fd);
		if (h && h->cb) {
			h->cb(fd, events[i].events, h->data);
		}
	}
}

void run() {
	struct epoll_event events[MAX_EVENTS];
	uint64_t last_periodic_ms = util::timeUsec() / 1000;

	for (;;) {
		uint64_t now_ms = util::timeUsec() / 1000;
		int timeout_ms = -1;
		if (current_ctx.periodics_count > 0) {
			timeout_ms =
			    std::max(0, (int)(kPeriodicIntervalMs - (now_ms - last_periodic_ms)));
		}

		int nfds = epoll_wait(current_ctx.epoll_fd, events, MAX_EVENTS, timeout_ms);
		if (nfds == -1) {
			if (errno == EINTR) {
				continue;
			}
			PLOG_W("epoll_wait");
			break;
		}

		dispatchEvents(events, nfds);

		now_ms = util::timeUsec() / 1000;
		if (current_ctx.periodics_count > 0 &&
		    now_ms - last_periodic_ms >= kPeriodicIntervalMs) {
			last_periodic_ms = now_ms;
			size_t count = current_ctx.periodics_count;
			for (size_t i = 0; i < count; ++i) {
				current_ctx.periodics[i]();
			}
		}

		if (current_ctx.stop_requested) {
			break;
		}
	}
}

/* --- event loop ---------------------------------------- */

/* --- pipe setup (listen mode) -------------------------- */

static bool createProxyPipes(int connfd, ProxyPipes* pipes) {
	int in[2];
	int out[2];

	if (pipe2(in, O_CLOEXEC) != 0) {
		PLOG_W("pipe2(in)");
		return false;
	}
	pipes->child_in = in[0];
	pipes->parent_out = in[1];

	if (pipe2(out, O_CLOEXEC) != 0) {
		PLOG_W("pipe2(out)");
		pipes->closeAll();
		return false;
	}
	pipes->parent_in = out[0];
	pipes->child_out = out[1];

	/* Proxy side must be non-blocking for splice() */
	if (!util::setNonBlock(pipes->parent_in) || !util::setNonBlock(pipes->parent_out)) {
		pipes->closeAll();
		return false;
	}

	pipes->connfd = connfd;
	return true;
}

/* --- teardown ------------------------------------------ */

static void timeoutCb() {
	subproc::checkTimeouts(current_ctx.nsj, current_ctx.pid, current_ctx.start_time,
	    current_ctx.remote_txt, current_ctx.pidfd);
	nstun_periodic();
}

void cleanUpAndExit() {
	nstun_destroy_parent();
	unotify::stop();
	sockproxy::stop();

	current_ctx.pipes.closeAll();

	if (current_ctx.ipc_fd >= 0) {
		close(current_ctx.ipc_fd);
		current_ctx.ipc_fd = -1;
	}

	if (current_ctx.epoll_fd != -1) {
		close(current_ctx.epoll_fd);
		current_ctx.epoll_fd = -1;
	}

	current_ctx.periodics_count = 0;
	current_ctx.fd_handlers_count = 0;
	current_ctx.stop_requested = false;
}

void killAndExit() {
	if (current_ctx.pidfd >= 0) {
		util::syscall(__NR_pidfd_send_signal, current_ctx.pidfd, SIGKILL, 0, 0);
	}
	cleanUpAndExit();
}

/* --- epoll callbacks ----------------------------------- */

/*
 * pidfd became readable -> child is already dead.
 * Just signal the loop to exit; cleanUpAndExit() skips the kill.
 */
static void pidfdCb(int /* fd */, uint32_t /* events */, void* /* data */) {
	LOG_D("Child died (pidfd event), exiting monitor thread");
	current_ctx.stop_requested = true;
}

/*
 * IPC socketpair events:
 *   EPOLLIN      -> message from child (e.g. execve failure)
 *   EPOLLRDHUP   -> child closed its end (normal after execve)
 */
static void ipcFdCb(int ipc_fd, uint32_t events, void* /* data */) {
	if (events & EPOLLIN) {
		uint32_t id = 0;
		errno = 0;
		if (util::recvMsg(ipc_fd, &id, nullptr)) {
			LOG_D("IPC msg 0x%08x from fd=%d", id, ipc_fd);
			if (id == monitor::MSG_TAG_ERROR) {
				LOG_W("Child reported error (execve failed)");
				current_ctx.stop_requested = true;
			}
		} else {
			if (errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				PLOG_W("recvMsg from ipc_fd failed unexpectedly");
			}
		}
	}

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
		LOG_D("ipc_fd=%d closed (child reached execve), unregistering", ipc_fd);
		removeFd(ipc_fd);
		close(ipc_fd);
		current_ctx.ipc_fd = -1;
	}
}

/* --- IPC setup handshake ------------------------------- */

/*
 * Receive setup FDs from the child (tap, unotify, etc.) until
 * MSG_TAG_READY_J2H signals that the child is ready to proceed.
 *
 * Returns true on success, false on error (caller should killAndExit).
 */
static bool receiveChildFds(int ipc_fd, nsj_t* nsj, pid_t pid, int pidfd) {
	bool received_tap = false;
	bool received_unotify = false;
	int fd = -1;
	bool fd_consumed = false;
	bool success = false;

	for (;;) {
		fd = -1;
		fd_consumed = false;

		struct pollfd pfds[2] = {
		    {
			.fd = ipc_fd,
			.events = POLLIN,
			.revents = 0,
		    },
		    {
			.fd = pidfd,
			.events = POLLIN,
			.revents = 0,
		    },
		};
		struct timespec ts = {
		    .tv_sec = kSetupTimeoutSec,
		    .tv_nsec = 0,
		};
		int res = ppoll(pfds, 2, &ts, nullptr);
		if (res == -1) {
			if (errno == EINTR) {
				continue;
			}
			PLOG_W("ppoll(ipc_fd, pidfd)");
			goto cleanup;
		}
		if (res == 0) {
			LOG_W("Timeout waiting for setup FDs from child");
			goto cleanup;
		}

		if (pfds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
			LOG_W("Child died during setup");
			goto cleanup;
		}

		if (!(pfds[0].revents & POLLIN)) {
			continue;
		}

		uint32_t id = 0;
		if (!util::recvMsg(ipc_fd, &id, &fd)) {
			LOG_W("Failed to receive IPC message from child");
			goto cleanup;
		}

		switch (id) {
		case monitor::MSG_TAG_READY_J2H:
			success = true;
			goto cleanup;

		case monitor::MSG_TAG_TAP:
			if (received_tap) {
				LOG_W("Duplicate TAP message from child");
				goto cleanup;
			}
			received_tap = true;
			if (!nstun_init_parent(fd, nsj, pid)) {
				LOG_W("nstun_init_parent failed");
				goto cleanup;
			}
			fd_consumed = true;
			break;

		case monitor::MSG_TAG_UNOTIFY:
			if (received_unotify) {
				LOG_W("Duplicate UNOTIFY message from child");
				goto cleanup;
			}
			received_unotify = true;
			LOG_D("Received unotif_fd=%d from child", fd);
			if (!unotify::start(nsj, fd)) {
				LOG_W("Failed to start unotify");
				goto cleanup;
			}
			fd_consumed = true;
			break;

		case monitor::MSG_TAG_ERROR:
			LOG_W("Child failed to launch");
			goto cleanup;

		default:
			LOG_W("Unknown IPC message type 0x%08x from child", id);
			goto cleanup;
		}

		if (!fd_consumed && fd >= 0) {
			close(fd);
		}
	}

cleanup:
	if (!fd_consumed && fd >= 0) {
		close(fd);
	}
	return success;
}

static void proxyCloseCb(void* /* data */) {
	ThreadCtx* ctx = &current_ctx;
	LOG_D("Proxy closed, killing child process (pid=%d)", ctx->pid);
	util::syscall(__NR_pidfd_send_signal, ctx->pidfd, SIGKILL, 0, 0);
	monitor::stop();
}

/* --- monitor thread ------------------------------------ */

struct MonitorArgs {
	nsj_t* nsj;
	pid_t pid;
	int ipc_fd;
	int pidfd;
	ProxyPipes pipes; /* copied by value; connfd < 0 means no proxy */
	time_t start_time;
	char remote_txt[128];
};

static bool setupJail(const MonitorArgs& args) {
	if (!receiveChildFds(args.ipc_fd, args.nsj, args.pid, args.pidfd)) {
		return false;
	}
	if (!util::sendMsg(args.ipc_fd, monitor::MSG_TAG_READY_H2J)) {
		LOG_W("Failed to send READY to child");
		return false;
	}
	return true;
}

static bool registerEventSources(const MonitorArgs& args) {
	if (!addFd(args.pidfd, EPOLLIN, pidfdCb, nullptr)) {
		return false;
	}

	if (current_ctx.pipes.connfd >= 0) {
		if (!sockproxy::start(&current_ctx.pipes.connfd, &current_ctx.pipes.parent_out,
			&current_ctx.pipes.parent_in, proxyCloseCb, nullptr)) {
			return false;
		}
	}

	if (!util::setNonBlock(args.ipc_fd) ||
	    !addFd(args.ipc_fd, EPOLLIN | EPOLLRDHUP, ipcFdCb, nullptr)) {
		return false;
	}

	return true;
}

static void monitorThread(MonitorArgs args) {
	/* -- Thread identity -- */
	char name[16];
	snprintf(name, sizeof(name), "nsj-mon-%d", args.pid);
	prctl(PR_SET_NAME, name, 0, 0, 0);

	sigset_t set;
	sigemptyset(&set);
	for (int sig : nssigs) {
		sigaddset(&set, sig);
	}
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	/* -- Initialize thread-local context -- */
	current_ctx.reset();
	current_ctx.nsj = args.nsj;
	current_ctx.pid = args.pid;
	current_ctx.pidfd = args.pidfd;
	current_ctx.ipc_fd = args.ipc_fd;
	current_ctx.pipes = args.pipes;
	current_ctx.start_time = args.start_time;
	snprintf(current_ctx.remote_txt, sizeof(current_ctx.remote_txt), "%s", args.remote_txt);

	LOG_I("Monitor thread started for pid=%d (ipc_fd=%d, pidfd=%d) '%s'", (int)args.pid,
	    args.ipc_fd, args.pidfd, current_ctx.remote_txt);

	/* -- Create epoll instance -- */
	current_ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (current_ctx.epoll_fd == -1) {
		LOG_W("epoll_create1 failed");
		killAndExit();
		return;
	}

	/* -- Phase 1 & 2: setup and ack -- */
	if (!setupJail(args)) {
		killAndExit();
		return;
	}

	/* -- Phase 3: register epoll sources -- */
	if (!registerEventSources(args)) {
		killAndExit();
		return;
	}

	/* -- Phase 4: run event loop -- */
	addPeriodic(timeoutCb);
	run();

	/* -- Phase 5: kill child (harmless if already dead) and clean up -- */
	util::syscall(__NR_pidfd_send_signal, current_ctx.pidfd, SIGKILL, 0, 0);
	cleanUpAndExit();
}

/* --- thread launcher ----------------------------------- */

static void startMonitorThread(
    nsj_t* nsj, pid_t pid, int ipc_fd, int pidfd, ProxyPipes* pipes, std::thread* thread_out) {
	MonitorArgs args = {
	    .nsj = nsj,
	    .pid = pid,
	    .ipc_fd = ipc_fd,
	    .pidfd = pidfd,
	    .pipes = pipes ? *pipes : ProxyPipes{},
	    .start_time = 0,
	    .remote_txt = {},
	};

	/* Copy child metadata on the main thread to avoid racing with reapAll */
	auto it = nsj->pids.find(pid);
	if (it != nsj->pids.end()) {
		args.start_time = it->second.start;
		snprintf(
		    args.remote_txt, sizeof(args.remote_txt), "%s", it->second.remote_txt.c_str());
	}

	*thread_out = std::thread(monitorThread, args);
}

/* --- signal handling helpers --------------------------- */

/*
 * Handle a fatal signal during the main-thread poll loop.
 * First signal: forward to children (or SIGKILL), close listen socket.
 * After 2s:     escalate to SIGKILL.
 * Returns true if we should break out of the outer loop.
 */
static bool handleShutdownSignal(nsj_t* nsj, int sig, time_t* shutdown_start, int* listenfd) {
	if (*shutdown_start == 0) {
		*shutdown_start = time(nullptr);
		subproc::killAll(nsj, nsj->njc.forward_signals() ? sig : SIGKILL);
		logs::logStop(sig);
		if (listenfd && *listenfd >= 0) {
			close(*listenfd);
			*listenfd = -1;
		}
	} else if (time(nullptr) - *shutdown_start >= kShutdownEscalationSec) {
		LOG_W("Processes did not exit after %ds, escalating to SIGKILL",
		    kShutdownEscalationSec);
		subproc::killAll(nsj, SIGKILL);
	}

	subproc::reapAll(nsj);
	return (subproc::countProc(nsj) == 0);
}

/* --- listen mode (-Ml) -------------------------------- */

int runListenMode(nsj_t* nsj) {
	int listenfd = net::getRecvSocket(nsj);
	if (listenfd == -1) {
		return EXIT_FAILURE;
	}

	time_t shutdown_start = 0;
	for (;;) {
		struct pollfd pfd = {
		    .fd = listenfd,
		    .events = POLLIN,
		    .revents = 0,
		};
		struct timespec ts = {
		    .tv_sec = kPollTimeoutSec,
		    .tv_nsec = 0,
		};
		int res = ppoll(&pfd, 1, &ts, nullptr);
		if (res == -1 && errno != EINTR) {
			PLOG_W("ppoll");
			break;
		}

		/* -- Shutdown path -- */
		int sig = nsjail::getSigFatal();
		if (sig > 0) {
			if (handleShutdownSignal(nsj, sig, &shutdown_start, &listenfd)) {
				break;
			}
			continue;
		}

		/* -- Accept new connection -- */
		if (res > 0 && listenfd >= 0 && (pfd.revents & POLLIN)) {
			int connfd = net::acceptConn(listenfd);
			if (connfd >= 0) {
				ProxyPipes pipes;
				if (createProxyPipes(connfd, &pipes)) {
					int pidfd = -1;
					int ipc_fd = -1;
					pid_t pid = subproc::runChild(nsj, connfd, pipes.child_in,
					    pipes.child_out, pipes.child_out, &pidfd, &ipc_fd);
					if (pid <= 0) {
						pipes.closeAll();
					} else {
						/* Parent doesn't need these */
						close(pipes.child_in);
						pipes.child_in = -1;
						close(pipes.child_out);
						pipes.child_out = -1;

						startMonitorThread(nsj, pid, ipc_fd, pidfd, &pipes,
						    &nsj->pids[pid].thread);
					}
				} else {
					close(connfd);
				}
			}
		}

		/* -- Housekeeping -- */
		subproc::reapAll(nsj);
		if (nsjail::shouldShowProc()) {
			nsjail::clearShowProc();
			subproc::displayProc(nsj);
		}
	}

	if (listenfd >= 0) {
		close(listenfd);
	}
	return EXIT_SUCCESS;
}

/* --- standalone mode (-Mo / -Me) ----------------------- */

static void waitForChild(nsj_t* nsj, int pidfd) {
	time_t shutdown_start = 0;
	for (;;) {
		struct pollfd pfd = {
		    .fd = pidfd,
		    .events = POLLIN,
		    .revents = 0,
		};
		struct timespec ts = {
		    .tv_sec = kPollTimeoutSec,
		    .tv_nsec = 0,
		};
		int res = ppoll(&pfd, 1, &ts, nullptr);
		if (res == -1 && errno != EINTR) {
			PLOG_W("ppoll");
			break;
		}

		/* -- Shutdown path -- */
		int sig = nsjail::getSigFatal();
		if (sig > 0) {
			if (handleShutdownSignal(nsj, sig, &shutdown_start, nullptr)) {
				break;
			}
		}

		if (res > 0 && (pfd.revents & (POLLIN | POLLERR | POLLHUP))) {
			break;
		}

		if (nsjail::shouldShowProc()) {
			nsjail::clearShowProc();
			subproc::displayProc(nsj);
		}
	}
}

int runStandaloneMode(nsj_t* nsj) {
	for (;;) {
		int pidfd = -1;
		int ipc_fd = -1;
		pid_t pid = subproc::runChild(nsj, /* netfd= */ -1, STDIN_FILENO, STDOUT_FILENO,
		    STDERR_FILENO, &pidfd, &ipc_fd);
		if (pid == -1) {
			LOG_E("Couldn't launch the child process");
			return 0xff;
		}
		time_t start_time = nsj->pids[pid].start;

		startMonitorThread(nsj, pid, ipc_fd, pidfd, nullptr, &nsj->pids[pid].thread);

		waitForChild(nsj, pidfd);

		/* Main thread reaps the child and joins its monitor thread */
		subproc::reapProc(nsj, pid, true);

		if (subproc::countProc(nsj) == 0) {
			if (nsj->njc.mode() == nsjail::Mode::ONCE) {
				return nsj->exit_status;
			}

			time_t now = time(nullptr);
			if (now - start_time < kPollTimeoutSec) {
				LOG_I("Child exited too quickly, rate-limiting respawn");
				struct timespec ts = {
				    .tv_sec = kPollTimeoutSec,
				    .tv_nsec = 0,
				};
				ppoll(nullptr, 0, &ts, nullptr);
			}

			/* Daemon mode: check for pending fatal signals before respawning.
			 * Without this, a SIGINT arriving during reapProc could spawn an
			 * unwanted new child (Infinite Daemon Loop Law, goal.md #4). */
			if (nsjail::getSigFatal() > 0) {
				return nsj->exit_status;
			}
		}
	}
	/* not reached */
}

}  // namespace monitor
