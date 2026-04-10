/*
 * nsjail - socket proxy for listen mode (-Ml)
 * -----------------------------------------
 *
 * Proxies data between an external TCP connection (sock_fd) and the
 * child process's stdin/stdout pipes using splice(2) for zero-copy
 * transfer.
 *
 * Two independent half-duplex channels:
 *   sock_fd  -> pipe_in   (network to child stdin)
 *   pipe_out -> sock_fd   (child stdout to network)
 *
 * Each channel drains independently with half-close semantics.
 * When both channels are done, the proxy tears itself down and
 * signals the monitor to stop the event loop.
 */

#include "sockproxy.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logs.h"
#include "monitor.h"
#include "util.h"

namespace sockproxy {

static constexpr size_t kSpliceChunkSize = 65536;
static constexpr int kMaxSpliceLoops = 16;

/* --- connection state ---------------------------------- */

struct channel_t {
	int pipe_fd = -1;
	bool blocked = false;
	bool registered = false;
};

struct conn_t {
	int sock_fd = -1;
	bool sock_registered = false;
	channel_t sock_to_pipe;
	channel_t pipe_to_sock;
	on_close_cb_t close_cb = nullptr;
	void* cb_data = nullptr;
};

static thread_local conn_t current_conn;

/* --- helpers ------------------------------------------- */

/*
 * Remove an FD from epoll, close it, and invalidate the slot.
 * Safe to call with *fd == -1 (no-op).
 */
static void closeAndUnregister(channel_t* chan) {
	if (chan->pipe_fd >= 0) {
		if (chan->registered) {
			monitor::removeFd(chan->pipe_fd);
			chan->registered = false;
		}
		close(chan->pipe_fd);
		chan->pipe_fd = -1;
	}
}

/*
 * Tear down an entire connection: unregister all FDs from epoll,
 * close everything, and clear the state.
 */
static void teardownConn(conn_t* conn) {
	if (!conn) {
		return;
	}
	closeAndUnregister(&conn->sock_to_pipe);
	closeAndUnregister(&conn->pipe_to_sock);
	if (conn->sock_fd >= 0) {
		if (conn->sock_registered) {
			monitor::removeFd(conn->sock_fd);
			conn->sock_registered = false;
		}
		close(conn->sock_fd);
		conn->sock_fd = -1;
	}
}

/*
 * Tear down connection and notify monitor.
 */
static void conclude(conn_t* conn) {
	teardownConn(conn);
	if (conn->close_cb) {
		conn->close_cb(conn->cb_data);
	} else {
		monitor::stop();
	}
}

/* --- splice pump --------------------------------------- */

enum class PumpResult {
	kMoved,	  /* data transferred, loop again       */
	kEof,	  /* EOF or hard error -- close channel  */
	kBlocked, /* dest full, need EPOLLOUT on dest   */
	kDrained, /* source empty, need EPOLLIN on src  */
};

/*
 * One non-blocking splice(src -> dst).
 * Exactly one of src/dst must be a pipe end (splice(2) requirement).
 * On EAGAIN, FIONREAD on check_fd distinguishes "source empty"
 * from "destination full".
 */
static PumpResult splicePump(int src, int dst, int check_fd) {
	ssize_t r = TEMP_FAILURE_RETRY(
	    splice(src, nullptr, dst, nullptr, kSpliceChunkSize, SPLICE_F_NONBLOCK));

	if (r > 0) {
		return PumpResult::kMoved;
	}
	if (r == 0) {
		return PumpResult::kEof;
	}
	if (r == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
		PLOG_D("splice(src=%d, dst=%d) error", src, dst);
		return PumpResult::kEof;
	}

	/* EAGAIN: source empty or dest full? */
	int n = 0;
	if (ioctl(check_fd, FIONREAD, &n) == -1) {
		PLOG_W("ioctl(FIONREAD, fd=%d)", check_fd);
		return PumpResult::kEof;
	}
	return (n == 0) ? PumpResult::kDrained : PumpResult::kBlocked;
}

/*
 * Drain one direction until it can't proceed.
 * On EOF/error, *pipe_fd is removed from epoll and closed.
 * Returns false if the channel hit EOF (*pipe_fd is now -1).
 */
static bool drainChannel(int src, int dst, int check_fd, channel_t* chan) {
	int loops = 0;
	while (!chan->blocked && chan->pipe_fd >= 0) {
		switch (splicePump(src, dst, check_fd)) {
		case PumpResult::kMoved:
			if (++loops > kMaxSpliceLoops) {
				return true; /* Yield to event loop for fairness */
			}
			continue;
		case PumpResult::kEof:
			closeAndUnregister(chan);
			return false;
		case PumpResult::kBlocked:
			chan->blocked = true;
			return true;
		case PumpResult::kDrained:
			return true;
		}
	}
	return (chan->pipe_fd >= 0);
}

static void proxyPumpCb(int fd, uint32_t events, void* data);

static void updateFdMask(int fd, uint32_t events, bool* registered, conn_t* conn) {
	if (fd < 0) {
		return;
	}

	if (events != 0) {
		if (!*registered) {
			if (monitor::addFd(fd, events, proxyPumpCb, conn)) {
				*registered = true;
			}
		} else {
			monitor::modFd(fd, events);
		}
	} else {
		if (*registered) {
			monitor::removeFd(fd);
			*registered = false;
		}
	}
}

/*
 * Recompute epoll event masks for all three FDs.
 *
 * Per-direction logic:
 *   not blocked -> watch source for EPOLLIN  (data available)
 *       blocked -> watch dest for EPOLLOUT   (space available)
 */
static void updateMasks(conn_t* conn) {
	uint32_t sock_ev = 0;
	uint32_t pipe_in_ev = 0;
	uint32_t pipe_out_ev = 0;

	if (conn->sock_fd >= 0 && conn->sock_to_pipe.pipe_fd >= 0) {
		sock_ev |= EPOLLRDHUP;
	}

	/* sock -> pipe_in */
	if (!conn->sock_to_pipe.blocked && conn->sock_to_pipe.pipe_fd >= 0) {
		sock_ev |= EPOLLIN;
	}
	if (conn->sock_to_pipe.blocked && conn->sock_fd >= 0) {
		pipe_in_ev |= EPOLLOUT;
	}

	/* pipe_out -> sock */
	if (!conn->pipe_to_sock.blocked && conn->pipe_to_sock.pipe_fd >= 0) {
		pipe_out_ev |= EPOLLIN;
	}
	if (conn->pipe_to_sock.blocked && conn->pipe_to_sock.pipe_fd >= 0) {
		sock_ev |= EPOLLOUT;
	}

	updateFdMask(conn->sock_fd, sock_ev, &conn->sock_registered, conn);
	updateFdMask(conn->sock_to_pipe.pipe_fd, pipe_in_ev, &conn->sock_to_pipe.registered, conn);
	updateFdMask(conn->pipe_to_sock.pipe_fd, pipe_out_ev, &conn->pipe_to_sock.registered, conn);
}

/* --- epoll callback ------------------------------------ */

static void proxyPumpCb(int fd, uint32_t events, void* data) {
	conn_t* conn = static_cast<conn_t*>(data);

	LOG_D("proxyPumpCb fd=%d events=0x%x", fd, events);

	if (events & EPOLLERR) {
		LOG_D("EPOLLERR on fd=%d, tearing down connection", fd);
		conclude(conn);
		return;
	}

	bool handled = false;

	/* -- Direction 1: sock_fd -> pipe_in (network -> child stdin) -- */
	if (conn->sock_to_pipe.pipe_fd >= 0 && conn->sock_fd >= 0) {
		bool ready = false;
		if (fd == conn->sock_fd &&
		    (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))) {
			ready = true;
		}
		if (fd == conn->sock_to_pipe.pipe_fd &&
		    (events & (EPOLLOUT | EPOLLHUP | EPOLLERR))) {
			ready = true;
		}

		if (ready) {
			conn->sock_to_pipe.blocked = false;
			if (!drainChannel(conn->sock_fd, conn->sock_to_pipe.pipe_fd, conn->sock_fd,
				&conn->sock_to_pipe)) {
				LOG_D("sock->pipe EOF (client half-closed), closing child stdin");
			}
			handled = true;
		}
	}

	/* -- Direction 2: pipe_out -> sock_fd (child stdout -> network) -- */
	if (conn->pipe_to_sock.pipe_fd >= 0 && conn->sock_fd >= 0) {
		bool ready = false;
		if (fd == conn->pipe_to_sock.pipe_fd &&
		    (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))) {
			ready = true;
		}
		if (fd == conn->sock_fd && (events & EPOLLOUT)) {
			ready = true;
		}

		if (ready) {
			conn->pipe_to_sock.blocked = false;
			if (!drainChannel(conn->pipe_to_sock.pipe_fd, conn->sock_fd,
				conn->pipe_to_sock.pipe_fd, &conn->pipe_to_sock)) {
				LOG_D("pipe->sock EOF, half-closing socket write side");
				shutdown(conn->sock_fd, SHUT_WR);
			}
			handled = true;
		}
	}

	/*
	 * Socket broken (EPOLLHUP/EPOLLERR): stop feeding the child.
	 * pipe_out may still have buffered data but splice will fail
	 * writing to a dead socket, so both channels converge to -1.
	 */
	if (fd == conn->sock_fd && (events & (EPOLLHUP | EPOLLERR))) {
		LOG_D("Socket error/hup on sock_fd=%d, tearing down", fd);
		conclude(conn);
		return;
	}

	/* -- Both done: tear down proxy and signal monitor to stop -- */
	if (conn->sock_to_pipe.pipe_fd == -1 && conn->pipe_to_sock.pipe_fd == -1) {
		LOG_D("Proxy fully drained, tearing down");
		conclude(conn);
	} else if (handled) {
		updateMasks(conn);
	}
}

/* --- public API ---------------------------------------- */

bool start(int* connfd, int* pipe_in, int* pipe_out, on_close_cb_t cb, void* data) {
	conn_t* conn = &current_conn;
	conn->sock_fd = *connfd;
	conn->sock_to_pipe.pipe_fd = *pipe_in;
	conn->pipe_to_sock.pipe_fd = *pipe_out;
	conn->close_cb = cb;
	conn->cb_data = data;

	/* Belt-and-suspenders: make sock_fd non-blocking in addition to
	 * SPLICE_F_NONBLOCK, so FIONREAD probes and future read()/write()
	 * calls never block the event loop. */
	if (!util::setNonBlock(conn->sock_fd)) {
		conn->sock_fd = -1;
		conn->sock_to_pipe.pipe_fd = -1;
		conn->pipe_to_sock.pipe_fd = -1;
		return false;
	}

	if (!monitor::addFd(conn->sock_fd, EPOLLRDHUP, proxyPumpCb, conn)) {
		PLOG_E("addFd(sock_fd=%d)", conn->sock_fd);
		conn->sock_fd = -1;
		conn->sock_to_pipe.pipe_fd = -1;
		conn->pipe_to_sock.pipe_fd = -1;
		return false;
	}
	conn->sock_registered = true;

	if (!monitor::addFd(conn->sock_to_pipe.pipe_fd, EPOLLRDHUP, proxyPumpCb, conn)) {
		PLOG_E("addFd(pipe_in=%d)", conn->sock_to_pipe.pipe_fd);
		monitor::removeFd(conn->sock_fd);
		conn->sock_registered = false;
		conn->sock_fd = -1;
		conn->sock_to_pipe.pipe_fd = -1;
		conn->pipe_to_sock.pipe_fd = -1;
		return false;
	}
	conn->sock_to_pipe.registered = true;

	if (!monitor::addFd(conn->pipe_to_sock.pipe_fd, EPOLLRDHUP, proxyPumpCb, conn)) {
		PLOG_E("addFd(pipe_out=%d)", conn->pipe_to_sock.pipe_fd);
		monitor::removeFd(conn->sock_to_pipe.pipe_fd);
		conn->sock_to_pipe.registered = false;
		monitor::removeFd(conn->sock_fd);
		conn->sock_registered = false;
		conn->sock_fd = -1;
		conn->sock_to_pipe.pipe_fd = -1;
		conn->pipe_to_sock.pipe_fd = -1;
		return false;
	}
	conn->pipe_to_sock.registered = true;

	/* Success: proxy owns the FDs now, invalidate caller's copies */
	*connfd = -1;
	*pipe_in = -1;
	*pipe_out = -1;

	updateMasks(conn);
	return true;
}

void stop() {
	teardownConn(&current_conn);
}

}  // namespace sockproxy
