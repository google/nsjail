/*
 * nsjail - epoll-based event loop interface
 * -----------------------------------------
 *
 * Public API for the per-child monitor thread and its single-threaded
 * event loop.  Each child process gets one monitor thread that
 * multiplexes I/O from pidfd, unotify, sockproxy, and nstun sources.
 */

#ifndef NS_MONITOR_H
#define NS_MONITOR_H

#include <stdint.h>

struct nsj_t;

namespace monitor {

/* --- IPC message tags ---------------------------------- */

constexpr uint32_t quad(char a, char b, char c, char d) {
	return (static_cast<uint32_t>(a)) | (static_cast<uint32_t>(b) << 8) |
	       (static_cast<uint32_t>(c) << 16) | (static_cast<uint32_t>(d) << 24);
}

constexpr uint32_t MSG_TAG_TAP = quad('T', 'A', 'P', 'F');
constexpr uint32_t MSG_TAG_UNOTIFY = quad('S', 'E', 'C', 'F');
constexpr uint32_t MSG_TAG_READY_J2H = quad('R', 'D', 'J', 'H');
constexpr uint32_t MSG_TAG_READY_H2J = quad('R', 'D', 'H', 'J');
constexpr uint32_t MSG_TAG_ERROR = quad('E', 'R', 'R', 'F');

/* --- epoll loop API ------------------------------------ */

typedef void (*fdCb_t)(int fd, uint32_t events, void* data);
typedef void (*periodicCb_t)();

bool addFd(int fd, uint32_t events, fdCb_t cb, void* data);
bool removeFd(int fd);
bool modFd(int fd, uint32_t events);
void addPeriodic(periodicCb_t cb);
void stop();

/* --- entry points -------------------------------------- */

int runListenMode(nsj_t* nsj);
int runStandaloneMode(nsj_t* nsj);

}  // namespace monitor

#endif /* NS_MONITOR_H */
