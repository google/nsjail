#include "iface.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_arp.h>
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

bool configIface(nsj_t* nsj) {
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sock == -1) {
		PLOG_E("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
		return false;
	}
	defer {
		close(sock);
	};

	struct ifreq ifr = {};
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", nsj->njc.user_net().ns_iface().c_str());

	struct in_addr addr;
	struct sockaddr_in* sa = (struct sockaddr_in*)(&ifr.ifr_addr);

	/* Set IP Address */
	if (!nsj->njc.user_net().ip4().empty()) {
		if (inet_pton(AF_INET, nsj->njc.user_net().ip4().c_str(), &addr) != 1) {
			LOG_E("Cannot convert '%s' into an IPv4 address",
			    nsj->njc.user_net().ip4().c_str());
			return false;
		}
		sa->sin_family = AF_INET;
		sa->sin_addr = addr;
		if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
			PLOG_E("ioctl(SIOCSIFADDR, '%s')", nsj->njc.user_net().ip4().c_str());
			return false;
		}
	}

	/* Set Point-to-Point Destination Address (Host/GW) */
	if (!nsj->njc.user_net().gw4().empty()) {
		struct sockaddr_in* dst = (struct sockaddr_in*)(&ifr.ifr_dstaddr);
		if (inet_pton(AF_INET, nsj->njc.user_net().gw4().c_str(), &addr) != 1) {
			LOG_E("Cannot convert '%s' into an IPv4 GW address",
			    nsj->njc.user_net().gw4().c_str());
			return false;
		}
		dst->sin_family = AF_INET;
		dst->sin_addr = addr;
		if (ioctl(sock, SIOCSIFDSTADDR, &ifr) == -1) {
			PLOG_E("ioctl(SIOCSIFDSTADDR, '%s')", nsj->njc.user_net().gw4().c_str());
			return false;
		}
	}

	/* Set Netmask to /32 for PtP link */
	struct sockaddr_in* netmask = (struct sockaddr_in*)(&ifr.ifr_netmask);
	netmask->sin_family = AF_INET;
	netmask->sin_addr.s_addr = 0xFFFFFFFF;	// 255.255.255.255
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

	/* Set MTU - not critical */
	ifr.ifr_mtu = NSTUN_MTU;
	if (ioctl(sock, SIOCSIFMTU, &ifr) == -1) {
		PLOG_W("ioctl(SIOCSIFMTU, %zu)", NSTUN_MTU);
	}

	/* Add default route out of interface */
	struct rtentry rt = {};
	struct sockaddr_in* sdest = (struct sockaddr_in*)(&rt.rt_dst);
	struct sockaddr_in* smask = (struct sockaddr_in*)(&rt.rt_genmask);

	sdest->sin_family = AF_INET;
	sdest->sin_addr.s_addr = INADDR_ANY;
	smask->sin_family = AF_INET;
	smask->sin_addr.s_addr = INADDR_ANY;

	rt.rt_flags = RTF_UP; /* Device route, no gateway necessary for PtP */
	char rt_dev[IFNAMSIZ];
	snprintf(rt_dev, sizeof(rt_dev), "%s", nsj->njc.user_net().ns_iface().c_str());
	rt.rt_dev = rt_dev;

	if (ioctl(sock, SIOCADDRT, &rt) == -1) {
		if (errno != EEXIST && errno != ENETUNREACH) {
			PLOG_E("ioctl(SIOCADDRT, dev %s)", nsj->njc.user_net().ns_iface().c_str());
			return false;
		}
	}

	return true;
}

}  // namespace nstun
