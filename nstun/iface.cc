#include "iface.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logs.h"
#include "macros.h"
#include "net_defs.h"
#include "nsjail.h"
#include "nstun.h"

namespace nstun {

/* Not always exported by userspace headers */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

bool configIface(nsj_t* nsj) {
	struct ifreq ifr = {};
	struct in_addr addr;
	struct rtentry rt = {};
	char rt_dev[IFNAMSIZ];

	if (nsj->njc.user_net().ns_iface().length() >= IFNAMSIZ) {
		LOG_E("Interface name '%s' is too long (max %d)",
		    nsj->njc.user_net().ns_iface().c_str(), IFNAMSIZ - 1);
		return false;
	}

	int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}
	defer {
		close(sock);
	};

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());
	/* Set IP Address */
	if (!nsj->njc.user_net().ip4().empty()) {
		if (inet_pton(AF_INET, nsj->njc.user_net().ip4().c_str(), &addr) != 1) {
			LOG_E("Cannot convert '%s' into an IPv4 address",
			    nsj->njc.user_net().ip4().c_str());
			return false;
		}
		struct sockaddr_in sa = {};
		sa.sin_family = AF_INET;
		sa.sin_addr = addr;
		memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
		if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
			PLOG_E("ioctl(SIOCSIFADDR, '%s')", nsj->njc.user_net().ip4().c_str());
			return false;
		}
	}

	/* Set Point-to-Point Destination Address (Host/GW) */
	if (!nsj->njc.user_net().gw4().empty()) {
		ifr = {};
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());
		if (inet_pton(AF_INET, nsj->njc.user_net().gw4().c_str(), &addr) != 1) {
			LOG_E("Cannot convert '%s' into an IPv4 GW address",
			    nsj->njc.user_net().gw4().c_str());
			return false;
		}
		struct sockaddr_in dst_sa = {};
		dst_sa.sin_family = AF_INET;
		dst_sa.sin_addr = addr;
		memcpy(&ifr.ifr_dstaddr, &dst_sa, sizeof(dst_sa));
		if (ioctl(sock, SIOCSIFDSTADDR, &ifr) == -1) {
			PLOG_E("ioctl(SIOCSIFDSTADDR, '%s')", nsj->njc.user_net().gw4().c_str());
			return false;
		}
	}

	/* Set Netmask to /32 for PtP link */
	ifr = {};
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());
	struct sockaddr_in netmask_sa = {};
	netmask_sa.sin_family = AF_INET;
	netmask_sa.sin_addr.s_addr = 0xFFFFFFFF; /* 255.255.255.255 */
	memcpy(&ifr.ifr_netmask, &netmask_sa, sizeof(netmask_sa));
	if (ioctl(sock, SIOCSIFNETMASK, &ifr) == -1) {
		PLOG_E("ioctl(SIOCSIFNETMASK, 255.255.255.255)");
		return false;
	}

	/* Bring interface UP */
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(SIOCGIFFLAGS)");
		return false;
	}
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
		PLOG_E("ioctl(SIOCSIFFLAGS)");
		return false;
	}

	ifr = {};
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());
	ifr.ifr_mtu = NSTUN_MTU;
	if (ioctl(sock, SIOCSIFMTU, &ifr) == -1) {
		PLOG_E("ioctl(SIOCSIFMTU, %zu)", NSTUN_MTU);
		return false;
	}

	/* Add default route out of interface */
	struct sockaddr_in sdest_sa = {};
	sdest_sa.sin_family = AF_INET;
	sdest_sa.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &sdest_sa, sizeof(sdest_sa));

	struct sockaddr_in smask_sa = {};
	smask_sa.sin_family = AF_INET;
	smask_sa.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &smask_sa, sizeof(smask_sa));

	rt.rt_flags = RTF_UP; /* Device route, no gateway necessary for PtP */
	snprintf(rt_dev, sizeof(rt_dev), "%s", nsj->njc.user_net().ns_iface().c_str());
	rt.rt_dev = rt_dev;

	if (ioctl(sock, SIOCADDRT, &rt) == -1) {
		if (errno != EEXIST && errno != ENETUNREACH) {
			PLOG_E("ioctl(SIOCADDRT, dev %s)", nsj->njc.user_net().ns_iface().c_str());
			return false;
		}
	}

	/* Configure IPv6 address and route */
	if (!nsj->njc.user_net().ip6().empty()) {
		int sock6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (sock6 == -1) {
			PLOG_E("socket(AF_INET6, SOCK_DGRAM)");
			return false;
		}
		defer {
			close(sock6);
		};

		/* Get interface index */
		struct ifreq ifr6 = {};
		snprintf(ifr6.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());
		if (ioctl(sock6, SIOCGIFINDEX, &ifr6) == -1) {
			PLOG_E("ioctl(SIOCGIFINDEX) for IPv6");
			return false;
		}
		int ifindex = ifr6.ifr_ifindex;

		/* Set IPv6 address with /128 prefix */
		struct in6_ifreq ifr6_addr = {};
		if (inet_pton(AF_INET6, nsj->njc.user_net().ip6().c_str(), &ifr6_addr.ifr6_addr) !=
		    1) {
			LOG_E("Cannot convert '%s' into an IPv6 address",
			    nsj->njc.user_net().ip6().c_str());
			return false;
		}
		ifr6_addr.ifr6_prefixlen = 128;
		ifr6_addr.ifr6_ifindex = ifindex;

		if (ioctl(sock6, SIOCSIFADDR, &ifr6_addr) == -1) {
			PLOG_E(
			    "ioctl(SIOCSIFADDR) for IPv6 '%s'", nsj->njc.user_net().ip6().c_str());
			return false;
		}

		/* Add default IPv6 route via the interface (device route, no gateway) */
		struct in6_rtmsg rt6 = {};
		rt6.rtmsg_ifindex = ifindex;
		rt6.rtmsg_flags = RTF_UP;
		rt6.rtmsg_metric = 1;
		/* dst = ::0/0 (default route) is already zeroed */

		if (ioctl(sock6, SIOCADDRT, &rt6) == -1) {
			if (errno != EEXIST) {
				PLOG_E("ioctl(SIOCADDRT) for IPv6 default route");
				return false;
			}
		}

		LOG_D("IPv6 configured: %s/128 on %s", nsj->njc.user_net().ip6().c_str(),
		    nsj->njc.user_net().ns_iface().c_str());
	}

	return true;
}

}  // namespace nstun
