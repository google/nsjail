/*
 * Tests for the seccomp unotify argument decoder. The decoder reads the traced process' memory
 * with process_vm_readv(), so these tests "trace" their own process: every pointer passed in a
 * fake seccomp_notif points into this process' address space. Memory which ends right before an
 * inaccessible page is used to simulate a tracee whose buffers can be copied only partially.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "unotify/record.h"
#include "unotify/syscall.h"

static int failures = 0;

#define EXPECT(cond)                                                                               \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			fprintf(stderr, "%s:%d: EXPECT(%s) failed\n", __FILE__, __LINE__, #cond);  \
			failures++;                                                                \
		}                                                                                  \
	} while (0)

/* A readable+writable page followed by an inaccessible one */
struct GuardedPage {
	GuardedPage() {
		page_size = sysconf(_SC_PAGESIZE);
		void* m = mmap(nullptr, 2 * page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED || mprotect((char*)m + page_size, page_size, PROT_NONE) == -1) {
			perror("mmap/mprotect");
			_exit(1);
		}
		base = (char*)m;
	}
	~GuardedPage() {
		munmap(base, 2 * page_size);
	}
	/* Returns a pointer such that only 'len' bytes are accessible from it */
	char* tail(size_t len) {
		return base + page_size - len;
	}
	char* base;
	size_t page_size;
};

static unotify::SyscallRecord decode(int nr, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0,
    uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0) {
	struct seccomp_notif req = {};
	req.pid = getpid();
	req.data.nr = nr;
	req.data.args[0] = a0;
	req.data.args[1] = a1;
	req.data.args[2] = a2;
	req.data.args[3] = a3;
	req.data.args[4] = a4;
	req.data.args[5] = a5;
	unotify::SyscallRecord rec;
	unotify::parseSyscall(&req, &rec);
	return rec;
}

static bool hasArg(const unotify::SyscallRecord& rec, const std::string& arg) {
	return std::find(rec.args.begin(), rec.args.end(), arg) != rec.args.end();
}

#if defined(__NR_connect)
static unotify::SyscallRecord decodeConnect(int fd, const void* addr, socklen_t addrlen) {
	return decode(__NR_connect, fd, (uintptr_t)addr, addrlen);
}

static void testUnixAbstractMaxLength() {
	/* Abstract names may use every byte of sun_path, including the last one */
	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;
	memset(sun.sun_path + 1, 'A', sizeof(sun.sun_path) - 2);
	sun.sun_path[sizeof(sun.sun_path) - 1] = 'Z';

	auto rec = decodeConnect(-1, &sun, sizeof(sun));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_type == unotify::Stat_NetResource_Type_UNIX);
	EXPECT(rec.res.net_endpoint == "@" + std::string(sizeof(sun.sun_path) - 2, 'A') + "Z");
}

static void testUnixPathnameUnterminated() {
	/* The kernel accepts a pathname filling the whole sun_path without a trailing NUL */
	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;
	memset(sun.sun_path, 'p', sizeof(sun.sun_path));
	sun.sun_path[0] = '/';
	const std::string expected(sun.sun_path, sizeof(sun.sun_path));

	auto rec = decodeConnect(-1, &sun, sizeof(sun));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_endpoint == expected);
	EXPECT(rec.res.has_net_path);
	EXPECT(rec.res.net_path.path == expected);
}

static void testUnixPathname() {
	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, "/run/nsjail-test.sock");
	socklen_t len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path) + 1;

	auto rec = decodeConnect(-1, &sun, len);
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_endpoint == "/run/nsjail-test.sock");
	EXPECT(rec.res.net_path.path == "/run/nsjail-test.sock");
}

static void testUnixUnnamed() {
	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;

	auto rec = decodeConnect(-1, &sun, sizeof(sa_family_t));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_endpoint == "anonymous unix socket");
}

static void testInet() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin = {};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(5353);
	EXPECT(inet_pton(AF_INET, "192.0.2.1", &sin.sin_addr) == 1);

	auto rec = decodeConnect(fd, &sin, sizeof(sin));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_type == unotify::Stat_NetResource_Type_IPV4);
	EXPECT(rec.res.net_endpoint == "192.0.2.1");
	/* The port is reported if the socket's type could be determined */
	bool typed = hasArg(rec, "type=SOCK_DGRAM (IPPROTO_UDP)");
	EXPECT(rec.res.has_net_port == typed);
	if (typed) {
		EXPECT(rec.res.net_port == 5353);
	}
	close(fd);
}

static void testInet6() {
	struct sockaddr_in6 sin6 = {};
	sin6.sin6_family = AF_INET6;
	EXPECT(inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr) == 1);

	auto rec = decodeConnect(-1, &sin6, sizeof(sin6));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_type == unotify::Stat_NetResource_Type_IPV6);
	EXPECT(rec.res.net_endpoint == "2001:db8::1");

	/* RFC 2133 sockaddr_in6, without sin6_scope_id */
	rec = decodeConnect(-1, &sin6, offsetof(struct sockaddr_in6, sin6_scope_id));
	EXPECT(rec.res.has_net);
	EXPECT(rec.res.net_endpoint == "2001:db8::1");
}

static void testInetTooShort() {
	/* The address must not be made up from bytes the tracee didn't supply */
	struct sockaddr_in sin = {};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	auto rec = decodeConnect(-1, &sin, offsetof(struct sockaddr_in, sin_addr));
	EXPECT(!rec.res.has_net);

	struct sockaddr_in6 sin6 = {};
	sin6.sin6_family = AF_INET6;
	rec = decodeConnect(-1, &sin6, offsetof(struct sockaddr_in6, sin6_addr) + 4);
	EXPECT(!rec.res.has_net);
}

static void testSockaddrPartialCopy() {
	/* Only the first 8 bytes of the sockaddr_in6 are readable */
	GuardedPage page;
	struct sockaddr_in6 sin6 = {};
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(443);
	char* p = page.tail(8);
	memcpy(p, &sin6, 8);

	auto rec = decodeConnect(-1, p, sizeof(sin6));
	EXPECT(!rec.res.has_net);
	EXPECT(rec.res.net_endpoint.empty());

	/* The same for an abstract AF_UNIX name, which would come out truncated */
	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path + 1, "nsjail-test", 11);
	p = page.tail(8);
	memcpy(p, &sun, 8);
	rec = decodeConnect(-1, p, offsetof(struct sockaddr_un, sun_path) + 12);
	EXPECT(!rec.res.has_net);
}

static void testSockaddrBadLength() {
	struct sockaddr_storage ss = {};
	ss.ss_family = AF_INET;
	auto rec = decodeConnect(-1, &ss, sizeof(ss) + 1);
	EXPECT(!rec.res.has_net);
	rec = decodeConnect(-1, &ss, (socklen_t)-1);
	EXPECT(!rec.res.has_net);
	rec = decodeConnect(-1, nullptr, sizeof(struct sockaddr_in));
	EXPECT(!rec.res.has_net);
}
#endif /* defined(__NR_connect) */

#if defined(__NR_openat)
static void testPathStrings() {
	GuardedPage page;

	/* A NUL-terminated string which ends right before the inaccessible page */
	const char path[] = "/nsjail/test/path";
	char* p = page.tail(sizeof(path));
	memcpy(p, path, sizeof(path));
	auto rec = decode(__NR_openat, AT_FDCWD, (uintptr_t)p, O_RDONLY);
	EXPECT(rec.res.has_path1);
	EXPECT(rec.res.path1.path == "/nsjail/test/path");
	EXPECT(rec.res.path1.mode == unotify::Stat_Path_Mode_RDONLY);

	/* Unterminated: the string ends where the readable memory ends */
	p = page.tail(4);
	memcpy(p, "/abc", 4);
	rec = decode(__NR_openat, AT_FDCWD, (uintptr_t)p, O_RDONLY);
	EXPECT(rec.res.path1.path == "/abc");

	/* Unreadable and NULL pointers (the markers are resolved relative to the cwd) */
	rec = decode(__NR_openat, AT_FDCWD, (uintptr_t)page.tail(0), O_RDONLY);
	EXPECT(rec.res.path1.path.ends_with("<invalid_ptr>"));
	rec = decode(__NR_openat, AT_FDCWD, 0, O_RDONLY);
	EXPECT(rec.res.path1.path.ends_with("NULL"));
}
#endif /* defined(__NR_openat) */

#if defined(__NR_execve)
static void testArgv() {
	if (sizeof(void*) != sizeof(uint64_t)) {
		/* The decoder assumes 64-bit pointers for the native architecture */
		return;
	}
	GuardedPage page;
	const char* argv[] = {"/bin/true", "arg1", "arg2"};

	/* A NULL-terminated argv */
	const char* full[] = {argv[0], argv[1], nullptr};
	auto rec = decode(__NR_execve, (uintptr_t)argv[0], (uintptr_t)full, 0);
	EXPECT(hasArg(rec, "argv[0]=/bin/true"));
	EXPECT(hasArg(rec, "argv[1]=arg1"));
	EXPECT(!hasArg(rec, "argv[2]=arg2"));

	/*
	 * No NULL terminator, and the array ends in the middle of the 3rd pointer: only pointers
	 * which were copied in full can be used.
	 */
	size_t len = 2 * sizeof(uint64_t) + 4;
	char* p = page.tail(len);
	memcpy(p, argv, len);
	rec = decode(__NR_execve, (uintptr_t)argv[0], (uintptr_t)p, 0);
	EXPECT(hasArg(rec, "argv[0]=/bin/true"));
	EXPECT(hasArg(rec, "argv[1]=arg1"));
	EXPECT(std::none_of(rec.args.begin(), rec.args.end(),
	    [](const std::string& a) { return a.rfind("argv[2]=", 0) == 0; }));
}
#endif /* defined(__NR_execve) */

#if defined(__NR_openat2)
static void testOpenHow() {
	struct {
		uint64_t flags;
		uint64_t mode;
		uint64_t resolve;
	} how = {O_WRONLY | O_CREAT, 0600, 0x08 /* RESOLVE_NO_SYMLINKS */};

	auto rec = decode(
	    __NR_openat2, AT_FDCWD, (uintptr_t) "/nsjail/test", (uintptr_t)&how, sizeof(how));
	EXPECT(rec.res.path1.mode == unotify::Stat_Path_Mode_WRONLY);
	EXPECT(rec.res.path1.mode_extra == "O_CREAT");
	EXPECT(hasArg(rec, "resolve=8"));

	/* Only 'flags' is readable: openat2() would fail with EFAULT, nothing is decoded */
	GuardedPage page;
	char* p = page.tail(sizeof(how.flags));
	memcpy(p, &how, sizeof(how.flags));
	rec = decode(__NR_openat2, AT_FDCWD, (uintptr_t) "/nsjail/test", (uintptr_t)p, sizeof(how));
	EXPECT(rec.res.path1.mode == unotify::Stat_Path_Mode_UNSPECIFIED);
	EXPECT(rec.res.path1.mode_extra.empty());
	EXPECT(!hasArg(rec, "resolve=8"));
}
#endif /* defined(__NR_openat2) */

int main() {
#if defined(__NR_connect)
	testUnixAbstractMaxLength();
	testUnixPathnameUnterminated();
	testUnixPathname();
	testUnixUnnamed();
	testInet();
	testInet6();
	testInetTooShort();
	testSockaddrPartialCopy();
	testSockaddrBadLength();
#endif /* defined(__NR_connect) */
#if defined(__NR_openat)
	testPathStrings();
#endif /* defined(__NR_openat) */
#if defined(__NR_execve)
	testArgv();
#endif /* defined(__NR_execve) */
#if defined(__NR_openat2)
	testOpenHow();
#endif /* defined(__NR_openat2) */

	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	return 0;
}
