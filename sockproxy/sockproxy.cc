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

	/*
	 * Remove an FD from epoll, close it, and invalidate the slot.
	 * Safe to call with pipe_fd == -1 (no-op).
	 */
	void closeAndUnregister() {
		if (pipe_fd >= 0) {
			if (registered) {
				monitor::removeFd(pipe_fd);
				registered = false;
			}
			close(pipe_fd);
			pipe_fd = -1;
		}
	}
};

struct conn_t {
	int sock_fd = -1;
	bool sock_registered = false;
	channel_t sock_to_pipe;
	channel_t pipe_to_sock;
	on_close_cb_t close_cb = nullptr;
	void* cb_data = nullptr;

	/*
	 * Tear down an entire connection: unregister all FDs from epoll,
	 * close everything, and clear the state.
	 */
	void teardown() {
		sock_to_pipe.closeAndUnregister();
		pipe_to_sock.closeAndUnregister();
		if (sock_fd >= 0) {
			if (sock_registered) {
				monitor::removeFd(sock_fd);
				sock_registered = false;
			}
			close(sock_fd);
			sock_fd = -1;
		}
	}
};

static thread_local conn_t current_conn;

/*
 * Tear down connection and notify monitor.
 */
static void conclude(conn_t* conn) {
	conn->teardown();
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
[[nodiscard]] static bool drainChannel(int src, int dst, int check_fd, channel_t* chan) {
	int loops = 0;
	while (!chan->blocked && chan->pipe_fd >= 0) {
		switch (splicePump(src, dst, check_fd)) {
		case PumpResult::kMoved:
			if (++loops > kMaxSpliceLoops) {
				return true; /* Yield to event loop for fairness */
			}
			continue;
		case PumpResult::kEof:
			chan->closeAndUnregister();
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

[[nodiscard]] static bool updateFdMask(int fd, uint32_t events, bool* registered, conn_t* conn) {
	if (fd < 0) {
		return true;
	}

	if (events == 0) {
		if (*registered) {
			monitor::removeFd(fd);
			*registered = false;
		}
		return true;
	}

	if (*registered) {
		return monitor::modFd(fd, events);
	}

	if (monitor::addFd(fd, events, proxyPumpCb, conn)) {
		*registered = true;
		return true;
	}
	return false;
}

/*
 * Recompute epoll event masks for all three FDs.
 *
 * Per-direction logic:
 *   not blocked -> watch source for EPOLLIN  (data available)
 *       blocked -> watch dest for EPOLLOUT   (space available)
 */
[[nodiscard]] static bool updateMasks(conn_t* conn) {
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

	if (!updateFdMask(conn->sock_fd, sock_ev, &conn->sock_registered, conn)) {
		return false;
	}
	if (!updateFdMask(
		conn->sock_to_pipe.pipe_fd, pipe_in_ev, &conn->sock_to_pipe.registered, conn)) {
		return false;
	}
	if (!updateFdMask(
		conn->pipe_to_sock.pipe_fd, pipe_out_ev, &conn->pipe_to_sock.registered, conn)) {
		return false;
	}
	return true;
}

/* --- epoll callback helpers ---------------------------- */

static bool handleSockToPipe(conn_t* conn, int fd, uint32_t events) {
	if (conn->sock_to_pipe.pipe_fd < 0 || conn->sock_fd < 0) {
		return false;
	}
	bool ready = false;
	if (fd == conn->sock_fd && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
		ready = true;
	}
	if (fd == conn->sock_to_pipe.pipe_fd && (events & (EPOLLOUT | EPOLLHUP | EPOLLERR))) {
		ready = true;
	}

	if (ready) {
		conn->sock_to_pipe.blocked = false;
		if (!drainChannel(conn->sock_fd, conn->sock_to_pipe.pipe_fd, conn->sock_fd,
			&conn->sock_to_pipe)) {
			LOG_D("sock->pipe EOF (client half-closed), closing child stdin");
			/* Client half-closed. Keep the reverse channel alive
			 * to receive any remaining output from the child. */
		}
		return true;
	}
	return false;
}

static bool handlePipeToSock(conn_t* conn, int fd, uint32_t events) {
	if (conn->pipe_to_sock.pipe_fd < 0 || conn->sock_fd < 0) {
		return false;
	}
	bool ready = false;
	if (fd == conn->pipe_to_sock.pipe_fd && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
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
			if (shutdown(conn->sock_fd, SHUT_WR) == -1) {
				PLOG_W("shutdown(SHUT_WR) failed");
			}
		}
		return true;
	}
	return false;
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
	handled |= handleSockToPipe(conn, fd, events);
	handled |= handlePipeToSock(conn, fd, events);

	/*
	 * Socket broken (EPOLLHUP/EPOLLERR): stop feeding the child.
	 * pipe_out may still have buffered data but splice will fail
	 * writing to a dead socket, so both channels converge to -1.
	 */
	if (fd == conn->sock_fd && (events & EPOLLHUP)) {
		LOG_D("Socket hup on sock_fd=%d, tearing down", fd);
		conclude(conn);
		return;
	}

	/* -- Both done: tear down proxy and signal monitor to stop -- */
	if (conn->sock_to_pipe.pipe_fd == -1 && conn->pipe_to_sock.pipe_fd == -1) {
		LOG_D("Proxy fully drained, tearing down");
		conclude(conn);
	} else if (handled) {
		if (!updateMasks(conn)) {
			LOG_E("updateMasks failed in callback, tearing down");
			conclude(conn);
			return;
		}
	}
}

/* --- public API ---------------------------------------- */

[[nodiscard]] bool start(int* connfd, int* pipe_in, int* pipe_out, on_close_cb_t cb, void* data) {
	conn_t* conn = &current_conn;
	if (conn->sock_fd >= 0) {
		LOG_E("sockproxy: connection already active in this thread");
		return false;
	}
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

	if (!updateMasks(conn)) {
		PLOG_E("updateMasks failed during start");
		(void)updateFdMask(conn->sock_fd, 0, &conn->sock_registered, conn);
		(void)updateFdMask(
		    conn->sock_to_pipe.pipe_fd, 0, &conn->sock_to_pipe.registered, conn);
		(void)updateFdMask(
		    conn->pipe_to_sock.pipe_fd, 0, &conn->pipe_to_sock.registered, conn);
		conn->sock_fd = -1;
		conn->sock_to_pipe.pipe_fd = -1;
		conn->pipe_to_sock.pipe_fd = -1;
		return false;
	}

	/* Success: proxy owns the FDs now, invalidate caller's copies */
	*connfd = -1;
	*pipe_in = -1;
	*pipe_out = -1;
	return true;
}

void stop() {
	current_conn.teardown();
}

}  // namespace sockproxy
