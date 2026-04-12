#include "unotify/syscall.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <charconv>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "missing_defs.h"
#include "unotify/stats_internal.h"
#include "unotify/syscall_defs.h"
#include "util.h"

namespace unotify {

constexpr size_t kMaxArgs = 128;
constexpr size_t kMaxPathLen = 4096;
constexpr int kMaxArrayElements = 1024;
constexpr size_t kMaxTotalArgsLen = 8192;

static thread_local std::string g_read_str_buf(kMaxPathLen - 1, '\0');

static ssize_t readProcessMem(pid_t pid, void* local_addr, uint64_t remote_addr, size_t len) {
	struct iovec local = {
	    .iov_base = local_addr,
	    .iov_len = len,
	};
	struct iovec remote = {
	    .iov_base = (void*)remote_addr,
	    .iov_len = len,
	};
	return TEMP_FAILURE_RETRY(process_vm_readv(pid, &local, 1, &remote, 1, 0));
}

struct DecodeState {
	int current_dirfd = AT_FDCWD;
	FsStatParams* last_path = nullptr;
	std::string last_socket_type;
};

struct PtrBuf {
	uint8_t* buf = nullptr;
	PtrBuf() {
		buf = static_cast<uint8_t*>(
		    aligned_alloc(alignof(uint64_t), kMaxArgs * sizeof(uint64_t)));
	}
	~PtrBuf() {
		free(buf);
	}
};
static thread_local PtrBuf g_ptr_buf;

static uint8_t* get_ptr_buf() {
	return g_ptr_buf.buf;
}

/* Helper functions string/memory reading, path resolution, etc. */

static std::string getTypeStr(int type) {
	int base_type = type & 0xf;
	std::string res;
	static const struct {
		const int val;
		const char* const name;
	} types[] = {
	    NS_VALSTR_STRUCT(SOCK_STREAM),
	    NS_VALSTR_STRUCT(SOCK_DGRAM),
	    NS_VALSTR_STRUCT(SOCK_RAW),
	    NS_VALSTR_STRUCT(SOCK_RDM),
	    NS_VALSTR_STRUCT(SOCK_SEQPACKET),
	    NS_VALSTR_STRUCT(SOCK_DCCP),
	    NS_VALSTR_STRUCT(SOCK_PACKET),
	};
	bool found = false;
	for (const auto& i : types) {
		if (base_type == i.val) {
			res = i.name;
			found = true;
			break;
		}
	}
	if (!found) {
		res = std::to_string(base_type);
	}
	if (type & SOCK_CLOEXEC) {
		res += "|SOCK_CLOEXEC";
	}
	if (type & SOCK_NONBLOCK) {
		res += "|SOCK_NONBLOCK";
	}
	return res;
}

static std::string getProtocolStr(int proto) {
	if (proto == 0) {
		return "0";
	}
	static const struct {
		const int val;
		const char* const name;
	} protos[] = {
	    NS_VALSTR_STRUCT(IPPROTO_IP),
	    NS_VALSTR_STRUCT(IPPROTO_ICMP),
	    NS_VALSTR_STRUCT(IPPROTO_IGMP),
	    NS_VALSTR_STRUCT(IPPROTO_IPIP),
	    NS_VALSTR_STRUCT(IPPROTO_TCP),
	    NS_VALSTR_STRUCT(IPPROTO_EGP),
	    NS_VALSTR_STRUCT(IPPROTO_PUP),
	    NS_VALSTR_STRUCT(IPPROTO_UDP),
	    NS_VALSTR_STRUCT(IPPROTO_IDP),
	    NS_VALSTR_STRUCT(IPPROTO_TP),
	    NS_VALSTR_STRUCT(IPPROTO_DCCP),
	    NS_VALSTR_STRUCT(IPPROTO_IPV6),
	    NS_VALSTR_STRUCT(IPPROTO_RSVP),
	    NS_VALSTR_STRUCT(IPPROTO_GRE),
	    NS_VALSTR_STRUCT(IPPROTO_ESP),
	    NS_VALSTR_STRUCT(IPPROTO_AH),
	    NS_VALSTR_STRUCT(IPPROTO_MTP),
	    NS_VALSTR_STRUCT(IPPROTO_BEETPH),
	    NS_VALSTR_STRUCT(IPPROTO_ENCAP),
	    NS_VALSTR_STRUCT(IPPROTO_PIM),
	    NS_VALSTR_STRUCT(IPPROTO_COMP),
	    NS_VALSTR_STRUCT(IPPROTO_SCTP),
	    NS_VALSTR_STRUCT(IPPROTO_UDPLITE),
	    NS_VALSTR_STRUCT(IPPROTO_MPLS),
	    NS_VALSTR_STRUCT(IPPROTO_RAW),
	    NS_VALSTR_STRUCT(IPPROTO_ICMPV6),
	};
	for (const auto& i : protos) {
		if (proto == i.val) {
			return i.name;
		}
	}
	return std::to_string(proto);
}

static std::string getSocketType(pid_t pid, int target_fd, int pidfd) {
	bool close_pidfd = false;
	if (pidfd < 0) {
		pidfd = util::syscall(__NR_pidfd_open, pid, 0);
		if (pidfd < 0) {
			if (errno != ESRCH) {
				PLOG_W("pidfd_open(pid=%d) failed", pid);
			}
			return "";
		}
		close_pidfd = true;
		fcntl(pidfd, F_SETFD, FD_CLOEXEC);
	}

	int local_fd = util::syscall(__NR_pidfd_getfd, pidfd, target_fd, 0);
	if (close_pidfd) {
		close(pidfd);
	}
	if (local_fd < 0) {
		return "";
	}
	fcntl(local_fd, F_SETFD, FD_CLOEXEC);

	int type = 0, proto = 0;
	socklen_t len = sizeof(type);
	std::string type_str;
	if (getsockopt(local_fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
		type_str = getTypeStr(type);
	}
	len = sizeof(proto);
	if (getsockopt(local_fd, SOL_SOCKET, SO_PROTOCOL, &proto, &len) == 0) {
		std::string proto_str = getProtocolStr(proto);
		if (proto_str != "0") {
			type_str += " (" + proto_str + ")";
		}
	}
	close(local_fd);
	return type_str;
}

// NOTE: Returns a view into a thread-local buffer. The view is only valid
// until the next call to readStringFromMem in the same thread.
static std::string_view readStringFromMem(pid_t pid, uint64_t addr) {
	if (addr == 0) {
		return "NULL";
	}
	size_t total_read = 0;
	static size_t page_size = 0;
	if (page_size == 0) {
		long sz = sysconf(_SC_PAGESIZE);
		page_size = (sz > 0) ? (size_t)sz : 4096;
	}
	while (total_read < g_read_str_buf.size()) {
		uint64_t current_addr = addr + total_read;
		size_t bytes_to_boundary = page_size - (current_addr % page_size);
		size_t size_to_read =
		    std::min(g_read_str_buf.size() - total_read, bytes_to_boundary);

		ssize_t ret = readProcessMem(
		    pid, g_read_str_buf.data() + total_read, current_addr, size_to_read);
		if (ret <= 0) {
			if (total_read == 0) {
				return "<invalid_ptr>";
			}
			break;
		}
		size_t len = strnlen(g_read_str_buf.data() + total_read, (size_t)ret);
		total_read += (size_t)ret;
		if (len < (size_t)ret) {
			// Found null!
			return std::string_view(g_read_str_buf.data(), total_read - ret + len);
		}
	}
	if (total_read == g_read_str_buf.size()) {
		return "<truncated>";
	}
	return "<invalid_ptr>";
}

static void appendStringArrayFromMem(
    pid_t pid, uint64_t addr, bool is_32bit, const char* prefix, std::string& out) {
	if (addr == 0) {
		return;
	}

	uint8_t* ptr_buf = get_ptr_buf();
	if (!ptr_buf) {
		return;
	}

	uint64_t current_addr = addr;
	int idx = 0;
	size_t ptr_size = is_32bit ? sizeof(uint32_t) : sizeof(uint64_t);
	size_t buf_len = kMaxArgs * ptr_size;

	while (true) {
		ssize_t ret = readProcessMem(pid, ptr_buf, current_addr, buf_len);
		if (ret <= 0) {
			break;
		}

		int num_ptrs = ret / ptr_size;
		bool found_null = false;
		for (int i = 0; i < num_ptrs; i++) {
			uint64_t ptr = 0;
			if (is_32bit) {
				ptr = ((uint32_t*)ptr_buf)[i];
			} else {
				ptr = ((uint64_t*)ptr_buf)[i];
			}

			if (ptr == 0) {
				found_null = true;
				break;
			}
			if (idx >= kMaxArrayElements || out.length() >= kMaxTotalArgsLen) {
				out += "... <truncated> ";
				break;
			}
			char idx_buf[16];
			auto [p, ec] = std::to_chars(idx_buf, idx_buf + sizeof(idx_buf), idx++);
			if (ec == std::errc()) {
				out.append(prefix);
				out.append("[");
				out.append(idx_buf, p - idx_buf);
				out.append("]=");
			} else {
				out.append(prefix);
				out.append("[?]=");
			}
			out += readStringFromMem(pid, ptr);
			out += " ";
		}

		if (found_null || idx >= kMaxArrayElements || num_ptrs < (int)kMaxArgs ||
		    out.length() >= kMaxTotalArgsLen) {
			break;
		}
		current_addr += num_ptrs * ptr_size;
	}
}

static void getAbsPath(pid_t pid, int dirfd, std::string_view raw_path, std::string& out) {
	if (raw_path.empty() || raw_path[0] == '/') {
		out = raw_path;
		return;
	}

	std::string link_path;
	if (dirfd == AT_FDCWD || dirfd == -100) {
		link_path = "/proc/" + std::to_string(pid) + "/cwd";
	} else {
		link_path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd);
	}

	/* Reuse thread-local buffer to avoid heap allocation and stack pressure */
	static thread_local std::string g_abs_path_buf(PATH_MAX - 1, '\0');
	g_abs_path_buf.resize(PATH_MAX - 1);
	ssize_t len = readlink(link_path.c_str(), g_abs_path_buf.data(), g_abs_path_buf.size());
	if (len <= 0) {
		out = raw_path; /* fallback */
		return;
	}

	out.assign(g_abs_path_buf.data(), len);
	if (out.back() != '/') {
		out += '/';
	}
	out += raw_path;
}

static void getFileMode(int flags, FsStatParams* out) {
	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		out->mode = Stat_Path_Mode_RDONLY;
		break;
	case O_WRONLY:
		out->mode = Stat_Path_Mode_WRONLY;
		break;
	case O_RDWR:
		out->mode = Stat_Path_Mode_RDWR;
		break;
	default:
		out->mode = Stat_Path_Mode_UNSPECIFIED;
		break;
	}

	std::string mode_extra;
	static const struct {
		const int val;
		const char* const name;
	} openFlags[] = {
	    NS_VALSTR_STRUCT(O_CREAT),
	    NS_VALSTR_STRUCT(O_EXCL),
	    NS_VALSTR_STRUCT(O_NOCTTY),
	    NS_VALSTR_STRUCT(O_TRUNC),
	    NS_VALSTR_STRUCT(O_APPEND),
	    NS_VALSTR_STRUCT(O_NONBLOCK),
	    NS_VALSTR_STRUCT(O_DSYNC),
	    NS_VALSTR_STRUCT(FASYNC),
	    NS_VALSTR_STRUCT(O_DIRECT),
	    NS_VALSTR_STRUCT(O_LARGEFILE),
	    NS_VALSTR_STRUCT(O_DIRECTORY),
	    NS_VALSTR_STRUCT(O_NOFOLLOW),
	    NS_VALSTR_STRUCT(O_NOATIME),
	    NS_VALSTR_STRUCT(O_CLOEXEC),
	    NS_VALSTR_STRUCT(O_SYNC),
	    NS_VALSTR_STRUCT(O_PATH),
	    NS_VALSTR_STRUCT(O_TMPFILE),
	};
	for (const auto& i : openFlags) {
		if (flags & i.val) {
			mode_extra += "|";
			mode_extra += i.name;
		}
	}
	if (!mode_extra.empty()) {
		out->mode_extra = mode_extra.substr(1);	 // remove leading pipe
	}
}

static std::string getAccessMode(int mode) {
	if (mode == F_OK) {
		return "F_OK";
	}
	std::string acc;
	if (mode & R_OK) {
		acc += "R_OK|";
	}
	if (mode & W_OK) {
		acc += "W_OK|";
	}
	if (mode & X_OK) {
		acc += "X_OK|";
	}
	if (!acc.empty()) {
		acc.pop_back();
	}
	return acc;
}

static Stat_Path_Type getStatInfo(const std::string& path) {
	struct stat st;
	if (lstat(path.c_str(), &st) == -1) {
		return Stat_Path_Type_NONEXISTENT;
	}
	if (S_ISREG(st.st_mode)) {
		return Stat_Path_Type_REGULAR;
	}
	if (S_ISDIR(st.st_mode)) {
		return Stat_Path_Type_DIR;
	}
	if (S_ISCHR(st.st_mode)) {
		return Stat_Path_Type_CHR;
	}
	if (S_ISBLK(st.st_mode)) {
		return Stat_Path_Type_BLK;
	}
	if (S_ISFIFO(st.st_mode)) {
		return Stat_Path_Type_FIFO;
	}
	if (S_ISLNK(st.st_mode)) {
		return Stat_Path_Type_LINK;
	}
	if (S_ISSOCK(st.st_mode)) {
		return Stat_Path_Type_SOCK;
	}
	return Stat_Path_Type_UNKNOWN;
}

static void populatePathInfo(pid_t pid, int dirfd, uint64_t addr, FsStatParams* out_rec) {
	std::string_view raw_path = readStringFromMem(pid, addr);
	if (raw_path == "<invalid_ptr>") {
		out_rec->path = raw_path;
		out_rec->jail_type = Stat_Path_Type_UNKNOWN;
		out_rec->main_type = Stat_Path_Type_UNKNOWN;
		return;
	}
	getAbsPath(pid, dirfd, raw_path, out_rec->path);

	if (out_rec->path.empty() || out_rec->path[0] == '/') {
		out_rec->jail_type =
		    getStatInfo("/proc/" + std::to_string(pid) + "/root" + out_rec->path);
	} else {
		std::string rel_base;
		if (dirfd == AT_FDCWD || dirfd == -100) {
			rel_base = "/proc/" + std::to_string(pid) + "/cwd/";
		} else {
			rel_base =
			    "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd) + "/";
		}
		out_rec->jail_type = getStatInfo(rel_base + out_rec->path);
	}
	out_rec->main_type = getStatInfo(out_rec->path);
}

static void setPortIfApplicable(
    NetStatParams* net_rec, const std::string& socket_type_str, int port) {
	if (socket_type_str.find("SOCK_STREAM") != std::string::npos ||
	    socket_type_str.find("SOCK_DGRAM") != std::string::npos) {
		net_rec->has_port = true;
		net_rec->port = port;
	}
}

/* sockaddr decoder */

static void parseInetAddr(const struct sockaddr_storage& ss, ssize_t read_bytes,
    const std::string& socket_type_str, bool* out_has_net, NetStatParams* net_rec) {
	if (read_bytes < (ssize_t)sizeof(struct sockaddr_in)) {
		return;
	}
	char host[INET6_ADDRSTRLEN] = "unknown";
	const struct sockaddr_in* sin = (const struct sockaddr_in*)&ss;
	inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
	int port = ntohs(sin->sin_port);
	*out_has_net = true;
	net_rec->type = Stat_NetResource_Type_IPV4;
	net_rec->endpoint = std::string(host);
	setPortIfApplicable(net_rec, socket_type_str, port);
}

static void parseInet6Addr(const struct sockaddr_storage& ss, ssize_t read_bytes,
    const std::string& socket_type_str, bool* out_has_net, NetStatParams* net_rec) {
	if (read_bytes < (ssize_t)sizeof(struct sockaddr_in6)) {
		return;
	}
	char host[INET6_ADDRSTRLEN] = "unknown";
	const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)&ss;
	inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
	int port = ntohs(sin6->sin6_port);
	*out_has_net = true;
	net_rec->type = Stat_NetResource_Type_IPV6;
	net_rec->endpoint = std::string(host);
	setPortIfApplicable(net_rec, socket_type_str, port);
}

static void parseUnixAddr(const struct sockaddr_storage& ss, socklen_t addrlen, pid_t pid,
    bool* out_has_net, NetStatParams* net_rec) {
	struct sockaddr_un sun;
	if (addrlen > sizeof(sun)) {
		addrlen = sizeof(sun);
	}
	memcpy(&sun, &ss, addrlen);

	size_t path_len = 0;
	if (addrlen > sizeof(sa_family_t)) {
		path_len = addrlen - sizeof(sa_family_t);
	}
	if (path_len > sizeof(sun.sun_path)) {
		path_len = sizeof(sun.sun_path);
	}

	/* Ensure NUL termination for non-abstract paths */
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';
	std::string raw_path(sun.sun_path, strnlen(sun.sun_path, path_len));

	if (path_len == 0) {
		*out_has_net = true;
		net_rec->type = Stat_NetResource_Type_UNIX;
		net_rec->endpoint = "anonymous unix socket";
	} else if (sun.sun_path[0] != '\0') {
		std::string abs_path;
		getAbsPath(pid, AT_FDCWD, raw_path, abs_path);
		*out_has_net = true;
		net_rec->type = Stat_NetResource_Type_UNIX;
		net_rec->endpoint = abs_path;

		/* Also populate FS tracking for UNIX socket paths */
		net_rec->has_path = true;
		net_rec->path.path = abs_path;
		net_rec->path.jail_type =
		    getStatInfo("/proc/" + std::to_string(pid) + "/root" + abs_path);
		net_rec->path.main_type = getStatInfo(abs_path);
	} else {
		*out_has_net = true;
		net_rec->type = Stat_NetResource_Type_UNIX;
		net_rec->endpoint = "@" + std::string(sun.sun_path + 1, path_len - 1);
	}
}

static void parseSockaddr(struct seccomp_notif* req, NetStatParams* net_rec, bool* out_has_net,
    uint64_t addr, socklen_t addrlen, const std::string& socket_type_str) {
	if (addrlen > sizeof(struct sockaddr_storage) || addr == 0) {
		return;
	}

	struct sockaddr_storage ss = {};
	ssize_t read_bytes = readProcessMem(req->pid, &ss, addr, addrlen);
	if (read_bytes >= (ssize_t)sizeof(sa_family_t)) {
		switch (ss.ss_family) {
		case AF_INET:
			parseInetAddr(ss, read_bytes, socket_type_str, out_has_net, net_rec);
			break;
		case AF_INET6:
			parseInet6Addr(ss, read_bytes, socket_type_str, out_has_net, net_rec);
			break;
		case AF_UNIX:
			parseUnixAddr(ss, addrlen, req->pid, out_has_net, net_rec);
			break;
		case AF_NETLINK:
			*out_has_net = true;
			net_rec->type = Stat_NetResource_Type_NETLINK;
			net_rec->endpoint = "NETLINK";
			break;
		default:
			break;
		}
	}
}

/* String formatters for socket domain, type, protocol */

static std::string getDomainStr(int domain) {
	static const struct {
		const int val;
		const char* const name;
	} domains[] = {
	    NS_VALSTR_STRUCT(AF_UNIX),
	    NS_VALSTR_STRUCT(AF_LOCAL),
	    NS_VALSTR_STRUCT(AF_INET),
	    NS_VALSTR_STRUCT(AF_INET6),
	    NS_VALSTR_STRUCT(AF_IPX),
	    NS_VALSTR_STRUCT(AF_NETLINK),
	    NS_VALSTR_STRUCT(AF_X25),
	    NS_VALSTR_STRUCT(AF_AX25),
	    NS_VALSTR_STRUCT(AF_ATMPVC),
	    NS_VALSTR_STRUCT(AF_APPLETALK),
	    NS_VALSTR_STRUCT(AF_PACKET),
	    NS_VALSTR_STRUCT(AF_ALG),
	    NS_VALSTR_STRUCT(AF_VSOCK),
	};
	for (const auto& i : domains) {
		if (domain == i.val) {
			return i.name;
		}
	}
	return std::to_string(domain);
}

/* Decoded syscall result — groups all out-params of decodeSyscallArgs */

struct ParsedArgs {
	std::string args_str;
	bool has_p1 = false;
	FsStatParams p1;
	bool has_p2 = false;
	FsStatParams p2;
	bool has_net = false;
	NetStatParams net;
};

/* Generic arg decoder driven by ArgRole metadata from the table */

static void decodePathArg(pid_t pid, DecodeState& state, __u64 arg, ParsedArgs& out) {
	FsStatParams* target;
	if (!out.has_p1) {
		out.has_p1 = true;
		target = &out.p1;
	} else {
		out.has_p2 = true;
		target = &out.p2;
	}
	populatePathInfo(pid, state.current_dirfd, arg, target);
	state.last_path = target;
	state.current_dirfd = AT_FDCWD;
}

static void decodeDirfdArg(__u64 arg, ParsedArgs& out, DecodeState& state) {
	int dirfd = (int)arg;
	std::string arg_str =
	    "dirfd=" +
	    (dirfd == AT_FDCWD || dirfd == -100 ? std::string("AT_FDCWD") : std::to_string(dirfd));
	out.args_str += arg_str + " ";
	state.current_dirfd = dirfd;
}

static void decodeArgvArg(pid_t pid, __u64 arg, bool is_32bit, ParsedArgs& out) {
	appendStringArrayFromMem(pid, arg, is_32bit, "argv", out.args_str);
}

static void decodeEnvpArg(pid_t pid, __u64 arg, bool is_32bit, ParsedArgs& out) {
	appendStringArrayFromMem(pid, arg, is_32bit, "envp", out.args_str);
}

static void decodeFdArg(pid_t pid, __u64 arg, ParsedArgs& out, DecodeState& state, int pidfd) {
	state.last_socket_type = getSocketType(pid, (int)arg, pidfd);
	if (!state.last_socket_type.empty()) {
		out.args_str += "type=" + state.last_socket_type + " ";
	}
}

static void decodeSaddrArg(
    struct seccomp_notif* req, __u64 arg, int i, ParsedArgs& out, const DecodeState& state) {
	if (arg == 0) {
		return;
	}
	__u64* args = req->data.args;
	socklen_t addrlen = (i + 1 < 6) ? (socklen_t)args[i + 1] : 0;
	parseSockaddr(req, &out.net, &out.has_net, arg, addrlen, state.last_socket_type);
}

static void decodeOhowArg(pid_t pid, __u64 arg, ParsedArgs& out, const DecodeState& state) {
	struct {
		__u64 flags;
		__u64 mode;
		__u64 resolve;
	} how = {};
	ssize_t read_bytes = readProcessMem(pid, &how, arg, sizeof(how));
	if (read_bytes >= (ssize_t)sizeof(how.flags)) {
		if (state.last_path) {
			getFileMode((int)how.flags, state.last_path);
		}
		if (read_bytes >= (ssize_t)sizeof(how) && how.resolve != 0) {
			std::string arg_str = "resolve=" + std::to_string(how.resolve);
			out.args_str += arg_str + " ";
		}
	}
}

static void decodeSyscallArgs(
    struct seccomp_notif* req, const SyscallDef& def, int pidfd, ParsedArgs& out) {
	__u64* args = req->data.args;
	DecodeState state;

	bool is_32bit = false;
#ifdef AUDIT_ARCH_I386
	if (req->data.arch == AUDIT_ARCH_I386) {
		is_32bit = true;
	}
#endif
#ifdef AUDIT_ARCH_ARM
	if (req->data.arch == AUDIT_ARCH_ARM) {
		is_32bit = true;
	}
#endif

	for (int i = 0; i < 6; i++) {
		__u64 arg = args[i];
		switch (def.args[i]) {
		case ArgRole::SKIP:
			break;

		case ArgRole::PATH:
			decodePathArg(req->pid, state, arg, out);
			break;

		case ArgRole::DIRFD:
			decodeDirfdArg(arg, out, state);
			break;

		case ArgRole::FLAGS:
			if (state.last_path) {
				getFileMode((int)arg, state.last_path);
			}
			break;

		case ArgRole::OCTAL: {
			std::string arg_str = "mode=" + util::StrPrintf("0%o", (unsigned int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::ACCESS: {
			std::string arg_str = "mode=" + getAccessMode((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::UID: {
			std::string arg_str = "owner=" + std::to_string((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::GID: {
			std::string arg_str = "group=" + std::to_string((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::ARGV:
			decodeArgvArg(req->pid, arg, is_32bit, out);
			break;

		case ArgRole::ENVP:
			decodeEnvpArg(req->pid, arg, is_32bit, out);
			break;

		case ArgRole::FD:
			decodeFdArg(req->pid, arg, out, state, pidfd);
			break;

		case ArgRole::SADDR:
			decodeSaddrArg(req, arg, i, out, state);
			break;

		case ArgRole::ALEN:
			break; /* consumed by preceding SADDR */

		case ArgRole::IFLAGS: {
			std::string arg_str = "flags=" + std::to_string((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::DOMAIN: {
			std::string arg_str = "domain=" + getDomainStr((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::STYPE: {
			std::string arg_str = "type=" + getTypeStr((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::PROTO: {
			std::string arg_str = "protocol=" + getProtocolStr((int)arg);
			out.args_str += arg_str + " ";
			break;
		}

		case ArgRole::OHOW:
			decodeOhowArg(req->pid, arg, out, state);
			break;
		}
	}
}

/* Public API table-driven syscall name lookup + arg decoding */

void parseSyscall(struct seccomp_notif* req, int pidfd) {
	int nr = req->data.nr;
	const SyscallDef* def = nullptr;
	std::string sys_name;

	for (size_t i = 0; i < kTracedSyscallCount; ++i) {
		if (kTracedSyscalls[i].nr == nr) {
			sys_name = kTracedSyscalls[i].display_name;
			def = &kTracedSyscalls[i];
			break;
		}
	}

	if (sys_name.empty()) {
		sys_name = "sys_" + std::to_string(nr);
	}

	auto pa = std::make_unique<ParsedArgs>();
	if (def) {
		decodeSyscallArgs(req, *def, pidfd, *pa);
	}

	if (pa->has_p1) {
		addFsStat(pa->p1, sys_name, pa->args_str);
	}
	if (pa->has_p2) {
		addFsStat(pa->p2, sys_name, pa->args_str);
	}
	if (pa->has_net) {
		addNetStat(pa->net, sys_name, pa->args_str);
	}
}

}  // namespace unotify
