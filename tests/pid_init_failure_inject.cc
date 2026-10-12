#include <dlfcn.h>
#include <errno.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

pid_t original_pid;

__attribute__((constructor)) void rememberOriginalPid() {
	original_pid = getpid();
}

}  // namespace

extern "C" int prctl(
    int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	const char* failure = getenv("NSJAIL_TEST_FAIL_INIT");
	if (getpid() != original_pid && failure != nullptr &&
	    ((option == PR_SET_PDEATHSIG && strcmp(failure, "pdeathsig") == 0) ||
		(option == PR_SET_DUMPABLE && strcmp(failure, "dumpable") == 0))) {
		errno = EPERM;
		return -1;
	}
	return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

extern "C" int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact) {
	const char* failure = getenv("NSJAIL_TEST_FAIL_INIT");
	if (getpid() != original_pid && signum == SIGCHLD && failure != nullptr &&
	    strcmp(failure, "sigaction") == 0) {
		errno = EPERM;
		return -1;
	}

	using Sigaction = int (*)(int, const struct sigaction*, struct sigaction*);
	static const auto real_sigaction =
	    reinterpret_cast<Sigaction>(dlsym(RTLD_NEXT, "sigaction"));
	if (real_sigaction == nullptr) {
		errno = ENOSYS;
		return -1;
	}
	return real_sigaction(signum, act, oldact);
}
