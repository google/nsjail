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

#include <string>
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

static thread_local std::string g_read_str_buf(kMaxPathLen - 1, '\0');
static thread_local std::vector<uint32_t> g_ptrs32(kMaxArgs);
static thread_local std::vector<uint64_t> g_ptrs64(kMaxArgs);

/* Helper functions string/memory reading, path resolution, etc. */

static std::string getSocketType(pid_t pid, int target_fd) {
	int pidfd = util::syscall(__NR_pidfd_open, pid, 0);
	if (pidfd < 0) {
		return "";
	}
	fcntl(pidfd, F_SETFD, FD_CLOEXEC);

	int local_fd = util::syscall(__NR_pidfd_getfd, pidfd, target_fd, 0);
	close(pidfd);
	if (local_fd < 0) {
		return "";
	}
	fcntl(local_fd, F_SETFD, FD_CLOEXEC);

	int type = 0, proto = 0;
	socklen_t len = sizeof(type);
	std::string type_str;
	if (getsockopt(local_fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
		static const struct {
			const int val;
			const char* const name;
		} sockTypes[] = {
		    NS_VALSTR_STRUCT(SOCK_STREAM),
		    NS_VALSTR_STRUCT(SOCK_DGRAM),
		    NS_VALSTR_STRUCT(SOCK_RAW),
		    NS_VALSTR_STRUCT(SOCK_SEQPACKET),
		};
		bool found = false;
		for (const auto& i : sockTypes) {
			if (type == i.val) {
				type_str = i.name;
				found = true;
				break;
			}
		}
		if (!found) {
			type_str = "SOCK_TYPE_" + std::to_string(type);
		}
	}
	len = sizeof(proto);
	if (getsockopt(local_fd, SOL_SOCKET, SO_PROTOCOL, &proto, &len) == 0) {
		static const struct {
			const int val;
			const char* const name;
		} protoTypes[] = {
		    NS_VALSTR_STRUCT(IPPROTO_TCP),
		    NS_VALSTR_STRUCT(IPPROTO_UDP),
		    NS_VALSTR_STRUCT(IPPROTO_ICMP),
		    NS_VALSTR_STRUCT(IPPROTO_ICMPV6),
		};
		bool found = false;
		for (const auto& i : protoTypes) {
			if (proto == i.val) {
				type_str += " (";
				type_str += i.name;
				type_str += ")";
				found = true;
				break;
			}
		}
		if (!found && proto != 0) {
			type_str += " (proto_" + std::to_string(proto) + ")";
		}
	}
	close(local_fd);
	return type_str;
}

static std::string readStringFromMem(pid_t pid, uint64_t addr) {
	if (addr == 0) {
		return "NULL";
	}
	struct iovec local = {
	    .iov_base = g_read_str_buf.data(),
	    .iov_len = g_read_str_buf.size(),
	};
	struct iovec remote = {
	    .iov_base = (void*)addr,
	    .iov_len = g_read_str_buf.size(),
	};

	ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (ret <= 0) {
		return "<invalid_ptr>";
	}
	size_t len = strnlen(g_read_str_buf.data(), ret);
	return std::string(g_read_str_buf.data(), len);
}

static void appendStringArrayFromMem(
    pid_t pid, uint64_t addr, bool is_32bit, const char* prefix, std::string& out) {
	if (addr == 0) {
		return;
	}

	if (is_32bit) {
		struct iovec local = {
		    .iov_base = g_ptrs32.data(),
		    .iov_len = g_ptrs32.size() * sizeof(uint32_t),
		};
		struct iovec remote = {
		    .iov_base = (void*)addr,
		    .iov_len = g_ptrs32.size() * sizeof(uint32_t),
		};

		ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
		if (ret <= 0) {
			return;
		}

		int num_ptrs = ret / sizeof(uint32_t);
		for (int i = 0; i < num_ptrs; i++) {
			if (g_ptrs32[i] == 0) {
				break;
			}
			out += prefix;
			out += "[" + std::to_string(i) +
			       "]=" + readStringFromMem(pid, g_ptrs32[i]) + " ";
		}
	} else {
		struct iovec local = {
		    .iov_base = g_ptrs64.data(),
		    .iov_len = g_ptrs64.size() * sizeof(uint64_t),
		};
		struct iovec remote = {
		    .iov_base = (void*)addr,
		    .iov_len = g_ptrs64.size() * sizeof(uint64_t),
		};

		ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
		if (ret <= 0) {
			return;
		}

		int num_ptrs = ret / sizeof(uint64_t);
		for (int i = 0; i < num_ptrs; i++) {
			if (g_ptrs64[i] == 0) {
				break;
			}
			out += prefix;
			out += "[" + std::to_string(i) +
			       "]=" + readStringFromMem(pid, g_ptrs64[i]) + " ";
		}
	}
}

static std::string getAbsPath(pid_t pid, int dirfd, const std::string& raw_path) {
	if (raw_path.empty() || raw_path[0] == '/') {
		return raw_path;
	}

	std::string link_path;
	if (dirfd == AT_FDCWD || dirfd == -100) {
		link_path = "/proc/" + std::to_string(pid) + "/cwd";
	} else {
		link_path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd);
	}

	/* Heap-allocate to avoid stack pressure */
	std::string buf(PATH_MAX - 1, '\0');
	ssize_t len = readlink(link_path.c_str(), buf.data(), buf.size());
	if (len <= 0) {
		return raw_path;  // fallback
	}

	std::string abs_path(buf.data(), len);
	if (abs_path.back() != '/') {
		abs_path += '/';
	}
	abs_path += raw_path;
	return abs_path;
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
	std::string raw_path = readStringFromMem(pid, addr);
	if (raw_path == "<invalid_ptr>") {
		out_rec->path = raw_path;
		out_rec->jail_type = Stat_Path_Type_UNKNOWN;
		out_rec->main_type = Stat_Path_Type_UNKNOWN;
		return;
	}
	out_rec->path = getAbsPath(pid, dirfd, raw_path);

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
	if (socket_type_str.find("SOCK_STREAM") != std::string::npos ||
	    socket_type_str.find("SOCK_DGRAM") != std::string::npos) {
		net_rec->has_port = true;
		net_rec->port = port;
	}
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
	if (socket_type_str.find("SOCK_STREAM") != std::string::npos ||
	    socket_type_str.find("SOCK_DGRAM") != std::string::npos) {
		net_rec->has_port = true;
		net_rec->port = port;
	}
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
		std::string abs_path = getAbsPath(pid, AT_FDCWD, raw_path);
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
	struct iovec local = {
	    .iov_base = &ss,
	    .iov_len = addrlen,
	};
	struct iovec remote = {
	    .iov_base = (void*)addr,
	    .iov_len = addrlen,
	};
	ssize_t read_bytes = process_vm_readv(req->pid, &local, 1, &remote, 1, 0);
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

static ParsedArgs decodeSyscallArgs(struct seccomp_notif* req, const SyscallDef& def) {
	ParsedArgs out;
	__u64* args = req->data.args;
	int current_dirfd = AT_FDCWD;
	FsStatParams* last_path = nullptr;
	std::string last_socket_type;

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

		case ArgRole::PATH: {
			FsStatParams* target;
			if (!out.has_p1) {
				out.has_p1 = true;
				target = &out.p1;
			} else {
				out.has_p2 = true;
				target = &out.p2;
			}
			populatePathInfo(req->pid, current_dirfd, arg, target);
			last_path = target;
			current_dirfd = AT_FDCWD;
			break;
		}

		case ArgRole::DIRFD: {
			int dirfd = (int)arg;
			std::string arg_str =
			    "dirfd=" + (dirfd == AT_FDCWD || dirfd == -100 ? std::string("AT_FDCWD")
									   : std::to_string(dirfd));
			out.args_str += arg_str + " ";
			current_dirfd = dirfd;
			break;
		}

		case ArgRole::FLAGS:
			if (last_path) {
				getFileMode((int)arg, last_path);
			}
			break;

		case ArgRole::OCTAL: {
			char buf[32];
			snprintf(buf, sizeof(buf), "0%o", (unsigned int)arg);
			std::string arg_str = "mode=" + std::string(buf);
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

		case ArgRole::ARGV: {
			appendStringArrayFromMem(req->pid, arg, is_32bit, "argv", out.args_str);
			break;
		}

		case ArgRole::ENVP: {
			appendStringArrayFromMem(req->pid, arg, is_32bit, "envp", out.args_str);
			break;
		}

		case ArgRole::FD: {
			/* Don't emit raw fd number — it splits dedup unnecessarily */
			last_socket_type = getSocketType(req->pid, (int)arg);
			if (!last_socket_type.empty()) {
				out.args_str += "type=" + last_socket_type + " ";
			}
			break;
		}

		case ArgRole::SADDR: {
			if (arg == 0) {
				break;
			}
			socklen_t addrlen = (i + 1 < 6) ? (socklen_t)args[i + 1] : 0;
			parseSockaddr(req, &out.net, &out.has_net, arg, addrlen, last_socket_type);
			break;
		}

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

		case ArgRole::OHOW: {
			struct {
				__u64 flags;
				__u64 mode;
				__u64 resolve;
			} how = {};
			struct iovec local = {
			    .iov_base = &how,
			    .iov_len = sizeof(how),
			};
			struct iovec remote = {
			    .iov_base = (void*)arg,
			    .iov_len = sizeof(how),
			};
			ssize_t read_bytes = process_vm_readv(req->pid, &local, 1, &remote, 1, 0);
			if (read_bytes >= (ssize_t)sizeof(how.flags)) {
				if (last_path) {
					getFileMode((int)how.flags, last_path);
				}
				if (read_bytes >= (ssize_t)sizeof(how) && how.resolve != 0) {
					std::string arg_str =
					    "resolve=" + std::to_string(how.resolve);
					out.args_str += arg_str + " ";
				}
			}
			break;
		}
		}
	}
	return out;
}

/* Public API table-driven syscall name lookup + arg decoding */

void parseSyscall(struct seccomp_notif* req) {
	int nr = req->data.nr;
	const SyscallDef* def = nullptr;
	std::string sys_name;

	for (size_t i = 0; i < kTracedSyscallCount; i++) {
		if (kTracedSyscalls[i].nr == nr) {
			sys_name = kTracedSyscalls[i].display_name;
			def = &kTracedSyscalls[i];
			break;
		}
	}

	if (sys_name.empty()) {
		sys_name = "sys_" + std::to_string(nr);
	}

	ParsedArgs pa;
	if (def) {
		pa = decodeSyscallArgs(req, *def);
	}

	if (pa.has_p1) {
		addFsStat(pa.p1, sys_name, pa.args_str);
	}
	if (pa.has_p2) {
		addFsStat(pa.p2, sys_name, pa.args_str);
	}
	if (pa.has_net) {
		addNetStat(pa.net, sys_name, pa.args_str);
	}
}

}  // namespace unotify
