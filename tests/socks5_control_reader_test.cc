#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <ctime>
#include <vector>

#include "nstun/socks5_control_reader.h"

static void test_partial(const std::vector<uint8_t>& first,
    const std::vector<uint8_t>& remainder, size_t expected_length) {
	int fds[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	const int epfd = epoll_create1(EPOLL_CLOEXEC);
	assert(epfd >= 0);

	struct epoll_event registration = {
	    .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data = {.fd = fds[0]}};
	assert(epoll_ctl(epfd, EPOLL_CTL_ADD, fds[0], &registration) == 0);

	std::vector<uint8_t> received;
	time_t last_active = 0;
	assert(write(fds[1], first.data(), first.size()) == (ssize_t)first.size());

	struct epoll_event event = {};
	assert(epoll_wait(epfd, &event, 1, 0) == 1);
	auto result = nstun::read_socks5_control(
	    fds[0], &received, expected_length, &last_active);
	assert(result == nstun::Socks5ControlRead::PENDING);
	assert(received == first);
	assert(last_active != 0);

	/* Consumed partial replies must not keep waking level-triggered epoll. */
	for (int i = 0; i < 1000; i++) {
		assert(epoll_wait(epfd, &event, 1, 0) == 0);
	}

	assert(write(fds[1], remainder.data(), remainder.size()) ==
	    (ssize_t)remainder.size());
	assert(epoll_wait(epfd, &event, 1, 0) == 1);
	result = nstun::read_socks5_control(
	    fds[0], &received, expected_length, &last_active);
	assert(result == nstun::Socks5ControlRead::READY);
	assert(received.size() == expected_length);

	close(epfd);
	close(fds[0]);
	close(fds[1]);
}

static void test_eof_and_invalid_length() {
	int fds[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	std::vector<uint8_t> received;
	time_t last_active = 0;
	close(fds[1]);

	assert(nstun::read_socks5_control(fds[0], &received, 2, &last_active) ==
	    nstun::Socks5ControlRead::CLOSED);
	assert(nstun::read_socks5_control(fds[0], &received, 513, &last_active) ==
	    nstun::Socks5ControlRead::CLOSED);
	close(fds[0]);
}

int main() {
	test_partial({5}, {0}, 2);
	test_partial({5, 0, 0, 1}, {0, 0, 0, 0, 0, 0}, 10);
	test_partial({5, 0, 0, 4}, std::vector<uint8_t>(18), 22);
	test_eof_and_invalid_length();
	puts("SOCKS5 UDP control-reader regression: PASS");
}
