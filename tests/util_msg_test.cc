#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstring>

#include "util.h"

static size_t fd_count() {
	DIR* dir = opendir("/proc/self/fd");
	assert(dir != nullptr);
	size_t count = 0;
	while (const auto* entry = readdir(dir)) {
		if (entry->d_name[0] != '.') count++;
	}
	closedir(dir);
	return count;
}

static void send_fds(int sock, size_t payload_size, size_t count, int fd) {
	std::array<uint8_t, 8> payload = {};
	struct iovec iov = {.iov_base = payload.data(), .iov_len = payload_size};
	alignas(struct cmsghdr) char control[CMSG_SPACE(80 * sizeof(int))] = {};
	struct msghdr msg = {};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = CMSG_SPACE(count * sizeof(int));
	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
	for (size_t i = 0; i < count; i++) {
		memcpy(CMSG_DATA(cmsg) + i * sizeof(int), &fd, sizeof(fd));
	}
	assert(sendmsg(sock, &msg, 0) == (ssize_t)payload_size);
}

static void test_message(const char* test, int socket_type) {
	int socks[2];
	assert(socketpair(AF_UNIX, socket_type | SOCK_CLOEXEC, 0, socks) == 0);
	int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
	assert(source != -1);
	size_t before = fd_count();
	int received = -1;
	uint32_t message = 0x12345678;
	if (strcmp(test, "cloexec") == 0) {
		assert(util::sendFd(socks[0], source));
		received = util::recvFd(socks[1]);
		assert(received >= 0);
		int flags = fcntl(received, F_GETFD);
		assert(flags != -1 && (flags & FD_CLOEXEC));
		close(received);
	} else if (strcmp(test, "short") == 0) {
		send_fds(socks[0], 1, 1, source);
		assert(!util::recvMsg(socks[1], &message, &received));
		assert(message == 0x12345678);
		assert(received == -1);
	} else if (strcmp(test, "truncated_control") == 0) {
		send_fds(socks[0], sizeof(uint32_t), 80, source);
		assert(!util::recvMsg(socks[1], &message, &received));
		assert(message == 0x12345678);
		assert(received == -1);
	} else if (strcmp(test, "oversized") == 0) {
		send_fds(socks[0], 8, 1, source);
		assert(!util::recvMsg(socks[1], &message, &received));
		assert(message == 0x12345678);
		assert(received == -1);
	} else if (strcmp(test, "extra_fds") == 0) {
		send_fds(socks[0], sizeof(uint32_t), 3, source);
		assert(util::recvMsg(socks[1], nullptr, &received));
		assert(received >= 0);
		close(received);
	} else if (strcmp(test, "no_output") == 0) {
		send_fds(socks[0], sizeof(uint32_t), 1, source);
		assert(util::recvMsg(socks[1], nullptr, nullptr));
	} else {
		assert(false);
	}
	assert(fd_count() == before);
	close(source);
	close(socks[0]);
	close(socks[1]);
}

int main() {
	for (int socket_type : {SOCK_STREAM, SOCK_SEQPACKET}) {
		for (const char* test :
		    {"cloexec", "short", "truncated_control", "extra_fds", "no_output"}) {
			test_message(test, socket_type);
		}
	}
	test_message("oversized", SOCK_SEQPACKET);
	puts("util_msg_test: passed");
}
