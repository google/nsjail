#include "ip.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "icmp.h"
#include "logs.h"
#include "tcp.h"
#include "udp.h"

namespace nstun {

/*
 * Skip IPv6 extension headers to locate the first L4 header.
 *
 * Returns the L4 protocol number (e.g. IPPROTO_TCP) on success,
 * or -1 if the chain is malformed, too deep, or contains a fragment
 * (which nstun does not reassemble).
 *
 * `ptr` and `rem` are advanced past each extension header so the
 * caller can read the L4 header directly from `ptr`.
 */
static int skip_ipv6_ext_headers(int next_header, const uint8_t*& ptr, size_t& rem) {
	constexpr int MAX_EXT = 8; /* Defense: cap chain depth */
	for (int i = 0; i < MAX_EXT; ++i) {
		ssize_t ext_len;
		switch (next_header) {
		case IPPROTO_HOPOPTS: /* Hop-by-Hop Options */
		case IPPROTO_DSTOPTS: /* Destination Options */
		case IPPROTO_ROUTING: /* Routing */
		case 139:	      /* Host Identity Protocol */
		case 140: {	      /* Shim6 */
			if (rem < 2) return -1;
			size_t len = ((size_t)ptr[1] + 1) * 8;
			ext_len = (len <= rem) ? (ssize_t)len : -1;
			break;
		}
		case IPPROTO_FRAGMENT:
			/* nstun does not reassemble fragments. Drop unconditionally
			 * to match IPv4 behavior and prevent L4 port-based rule
			 * bypass via non-first fragments. */
			return -1;
		case IPPROTO_AH: { /* Authentication Header */
			if (rem < 2) return -1;
			size_t len = ((size_t)ptr[1] + 2) * 4;
			ext_len = (len <= rem) ? (ssize_t)len : -1;
			break;
		}
		default:
			ext_len = 0; /* Not an extension header: this is the L4 protocol */
			break;
		}

		if (ext_len < 0) return -1;	      /* Malformed or unsupported */
		if (ext_len == 0) return next_header; /* Reached L4 */

		next_header = ptr[0]; /* Next Header field is first byte of ext header */
		ptr += ext_len;
		rem -= ext_len;
	}
	return -1; /* Extension header chain too deep */
}

static bool extract_l4_ports(
    int proto, const uint8_t* payload, size_t len, uint16_t* src_port, uint16_t* dest_port) {
	if (proto == IPPROTO_TCP && len >= sizeof(tcp_hdr)) {
		tcp_hdr tcp;
		memcpy(&tcp, payload, sizeof(tcp));
		*src_port = ntohs(tcp.source);
		*dest_port = ntohs(tcp.dest);
		return true;
	} else if (proto == IPPROTO_UDP && len >= sizeof(udp_hdr)) {
		udp_hdr udp;
		memcpy(&udp, payload, sizeof(udp));
		*src_port = ntohs(udp.source);
		*dest_port = ntohs(udp.dest);
		return true;
	}
	return false;
}

void handle_ip4(Context* ctx, const uint8_t* payload, size_t len) {
	if (len < sizeof(ip4_hdr)) {
		return;
	}

	ip4_hdr ip;
	memcpy(&ip, payload, sizeof(ip));
	uint8_t ihl = ip4_ihl(&ip) * 4;

	if (ihl < sizeof(ip4_hdr) || ihl > len) {
		LOG_D("Invalid IPv4 IHL");
		return;
	}

	uint16_t tot_len = ntohs(ip.tot_len);
	if (tot_len < ihl || tot_len > len) {
		LOG_D("Invalid IPv4 tot_len");
		return;
	}

	const uint8_t* l4_payload = payload + ihl;
	size_t l4_len = tot_len - ihl;

	/* Drop IP fragments: nstun does not reassemble, and non-first
	 * fragments have no L4 header - parsing them would bypass rules */
	if (ntohs(ip.frag_off) & 0x3FFF) {
		LOG_W("Dropping IPv4 fragment");
		return;
	}

	/* Validate IPv4 header checksum */
	if (compute_checksum(payload, ihl) != 0) {
		LOG_W("Invalid IPv4 header checksum, dropping");
		return;
	}

	if (ip.saddr != ctx->guest_ip4 && ip.saddr != 0) {
		LOG_W("Dropping packet with invalid source IP");
		return;
	}

	/* SSRF gate: reject packets to loopback, broadcast, or INADDR_ANY.
	 * This is the single authoritative check - L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * loopback intentionally (admin-controlled). */
	if (IN_LOOPBACK(ntohl(ip.daddr)) || ip.daddr == htonl(INADDR_ANY) ||
	    ip.daddr == htonl(INADDR_BROADCAST)) {
		char daddr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip.daddr, daddr_str, sizeof(daddr_str));
		LOG_W("Dropping packet destined to loopback, ANY, or broadcast: %s", daddr_str);
		return;
	}
	uint16_t src_port = 0, dest_port = 0;
	extract_l4_ports(ip.protocol, l4_payload, l4_len, &src_port, &dest_port);

	if (logs::getLogLevel() <= logs::DEBUG) {
		char saddr_str[INET_ADDRSTRLEN];
		char daddr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip.saddr, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET, &ip.daddr, daddr_str, sizeof(daddr_str));
		if (src_port != 0 && dest_port != 0) {
			LOG_D("IP packet: proto=%u, %s:%u -> %s:%u, len=%zu", ip.protocol,
			    saddr_str, src_port, daddr_str, dest_port, l4_len);
		} else {
			LOG_D("IP packet: proto=%u, %s -> %s, len=%zu", ip.protocol, saddr_str,
			    daddr_str, l4_len);
		}
	}

	switch (ip.protocol) {
	case IPPROTO_ICMP:
		LOG_D("Calling handle_icmp4");
		LOG_D("about to call handle_icmp4: ctx=%p, ip=%p, l4=%p, len=%zu", (void*)ctx,
		    (void*)&ip, (void*)l4_payload, l4_len);
		handle_icmp4(ctx, &ip, l4_payload, l4_len);
		break;
	case IPPROTO_UDP:
		handle_udp4(ctx, &ip, l4_payload, l4_len);
		break;
	case IPPROTO_TCP:
		handle_tcp4(ctx, &ip, l4_payload, l4_len);
		break;
	default:
		LOG_D("Unknown IPv4 protocol: %u", ip.protocol);
		break;
	}
}

void handle_ip6(Context* ctx, const uint8_t* payload, size_t len) {
	if (len < sizeof(ip6_hdr)) {
		return;
	}

	ip6_hdr ip6;
	memcpy(&ip6, payload, sizeof(ip6));
	uint16_t payload_len = ntohs(ip6.payload_len);

	if (payload_len + sizeof(ip6_hdr) > len) {
		LOG_D("Invalid IPv6 payload_len");
		return;
	}

	/* Source IP filtering */
	if (memcmp(ip6.saddr, ctx->guest_ip6, IPV6_ADDR_LEN) != 0) {
		struct in6_addr saddr;
		memcpy(&saddr, ip6.saddr, sizeof(saddr));
		if (IN6_IS_ADDR_LINKLOCAL(&saddr)) {
			/* Allow link-local addresses from guest on the local link */
			if (logs::getLogLevel() <= logs::DEBUG) {
				char saddr_str[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, ip6.saddr, saddr_str, sizeof(saddr_str));
				LOG_D("Allowing link-local source address: %s", saddr_str);
			}
		} else if (IN6_IS_ADDR_SITELOCAL(&saddr)) {
			if (logs::getLogLevel() <= logs::DEBUG) {
				char saddr_str[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, ip6.saddr, saddr_str, sizeof(saddr_str));
				LOG_D("Dropping IPv6 packet with site-local source address: %s",
				    saddr_str);
			}
			return;
		} else {
			char saddr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, ip6.saddr, saddr_str, sizeof(saddr_str));
			LOG_W("Dropping IPv6 packet with spoofed source address: %s", saddr_str);
			return;
		}
	}

	/* SSRF gate: reject packets to loopback, v4-mapped, link-local, or site-local.
	 * This is the single authoritative check - L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * ::1 intentionally (admin-controlled). */
	struct in6_addr daddr;
	memcpy(&daddr, ip6.daddr, sizeof(daddr));
	if (IN6_IS_ADDR_LOOPBACK(&daddr)) {
		if (logs::getLogLevel() <= logs::DEBUG) {
			char daddr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, ip6.daddr, daddr_str, sizeof(daddr_str));
			LOG_D("Dropping IPv6 packet to loopback: %s", daddr_str);
		}
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&daddr)) {
		if (logs::getLogLevel() <= logs::DEBUG) {
			char daddr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, ip6.daddr, daddr_str, sizeof(daddr_str));
			LOG_D("Dropping IPv6 packet to v4-mapped address (use IPv4 directly): %s",
			    daddr_str);
		}
		return;
	}
	if (IN6_IS_ADDR_V4COMPAT(&daddr)) {
		if (logs::getLogLevel() <= logs::DEBUG) {
			char daddr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, ip6.daddr, daddr_str, sizeof(daddr_str));
			LOG_D("Dropping IPv6 packet to v4-compatible address (deprecated): %s",
			    daddr_str);
		}
		return;
	}
	if (IN6_IS_ADDR_LINKLOCAL(&daddr) || IN6_IS_ADDR_SITELOCAL(&daddr)) {
		if (logs::getLogLevel() <= logs::DEBUG) {
			char daddr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, ip6.daddr, daddr_str, sizeof(daddr_str));
			LOG_D("Dropping IPv6 packet to link/site-local address: %s", daddr_str);
		}
		return;
	}
	/*
	 * Skip IPv6 extension headers to find the actual L4 protocol.
	 *
	 * RFC 8200 §4: Extension headers must be processed in order.
	 * Each header's "Next Header" field identifies what follows.
	 * We only need to find the L4 header, not process the extensions.
	 */
	const uint8_t* l4_payload = payload + sizeof(ip6_hdr);
	size_t remaining = payload_len;

	int l4_proto = skip_ipv6_ext_headers(ip6.next_header, l4_payload, remaining);
	if (l4_proto < 0) {
		LOG_D("Failed to parse IPv6 extension headers");
		return;
	}

	uint16_t src_port = 0, dest_port = 0;
	extract_l4_ports(l4_proto, l4_payload, remaining, &src_port, &dest_port);

	if (logs::getLogLevel() <= logs::DEBUG) {
		char saddr_str[INET6_ADDRSTRLEN];
		char daddr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ip6.saddr, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET6, ip6.daddr, daddr_str, sizeof(daddr_str));
		if (src_port != 0 && dest_port != 0) {
			LOG_D("IPv6 packet: next_header=%u, %s:%u -> %s:%u, len=%u", l4_proto,
			    saddr_str, src_port, daddr_str, dest_port, payload_len);
		} else {
			LOG_D("IPv6 packet: next_header=%u, %s -> %s, len=%u", l4_proto, saddr_str,
			    daddr_str, payload_len);
		}
	}

	switch (l4_proto) {
	case IPPROTO_ICMPV6:
		handle_icmp6(ctx, &ip6, l4_payload, remaining);
		break;
	case IPPROTO_UDP:
		handle_udp6(ctx, &ip6, l4_payload, remaining);
		break;
	case IPPROTO_TCP:
		handle_tcp6(ctx, &ip6, l4_payload, remaining);
		break;
	default:
		LOG_D("Unknown IPv6 next_header: %u", l4_proto);
		break;
	}
}

}  // namespace nstun
