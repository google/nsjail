// Regression harness for inherited high-numbered file descriptors.
// Built statically so the probe can run in a minimal chroot without /proc.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TEST_FD 2048
#define MARKER "nsjail-high-fd-regression\n"

static void fail(const char* what) {
	perror(what);
	exit(1);
}

static void block_close_range(void) {
	struct sock_filter filter[] = {
	    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close_range, 0, 1),
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
	    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
	    .filter = filter,
	};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fail("prctl(PR_SET_NO_NEW_PRIVS)");
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
		fail("prctl(PR_SET_SECCOMP)");
	}
}

static void ensure_fd_limit(void) {
	struct rlimit lim;
	if (getrlimit(RLIMIT_NOFILE, &lim) == -1) {
		fail("getrlimit(RLIMIT_NOFILE)");
	}
	if (lim.rlim_cur <= TEST_FD) {
		if (lim.rlim_max <= TEST_FD) {
			fprintf(stderr, "RLIMIT_NOFILE hard limit cannot accommodate fd %d\n", TEST_FD);
			exit(1);
		}
		lim.rlim_cur = TEST_FD + 1;
		if (setrlimit(RLIMIT_NOFILE, &lim) == -1) {
			fail("setrlimit(RLIMIT_NOFILE)");
		}
	}
}

static void launch(int argc, char** argv) {
	// Syntax: helper launch <secret-file> <nsjail> [nsjail arguments ...].
	if (argc < 5) {
		fprintf(stderr, "usage: %s launch <secret-file> <nsjail> [args ...]\n", argv[0]);
		exit(2);
	}
	ensure_fd_limit();
	int source = open(argv[2], O_RDONLY | O_CLOEXEC);
	if (source == -1) {
		fail("open(secret)");
	}
	if (dup2(source, TEST_FD) == -1) {
		fail("dup2(high fd)");
	}
	if (source != TEST_FD) {
		close(source);
	}
	// Deliberately make it inheritable. Only nsjail should sanitize it.
	if (fcntl(TEST_FD, F_SETFD, 0) == -1) {
		fail("fcntl(F_SETFD)");
	}
	block_close_range();
	execvp(argv[3], &argv[3]);
	fail("execvp(nsjail)");
}

static int probe(const char* expected) {
	if (strcmp(expected, "closed") == 0) {
		errno = 0;
		if (fcntl(TEST_FD, F_GETFD) == -1 && errno == EBADF) {
			return 0;
		}
		fprintf(stderr, "FAIL: inherited fd %d survived into the jail\n", TEST_FD);
		return 1;
	}
	if (strcmp(expected, "open") == 0) {
		char buf[sizeof(MARKER)] = {0};
		ssize_t n = read(TEST_FD, buf, sizeof(MARKER) - 1);
		if (n == (ssize_t)(sizeof(MARKER) - 1) && memcmp(buf, MARKER, sizeof(MARKER) - 1) == 0) {
			return 0;
		}
		fprintf(stderr, "FAIL: explicit --pass_fd did not preserve fd %d\n", TEST_FD);
		return 1;
	}
	fprintf(stderr, "unknown expectation: %s\n", expected);
	return 2;
}

int main(int argc, char** argv) {
	if (argc >= 2 && strcmp(argv[1], "launch") == 0) {
		launch(argc, argv);
	}
	if (argc == 3 && strcmp(argv[1], "probe") == 0) {
		return probe(argv[2]);
	}
	fprintf(stderr, "usage: %s {launch|probe} ...\n", argv[0]);
	return 2;
}
