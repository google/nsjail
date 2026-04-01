#include "ip.h"

#include <netinet/in.h>
#include <string.h>

#include "core.h"
#include "icmp.h"
#include "logs.h"
#include "tcp.h"
#include "udp.h"

namespace nstun {
void handle_ip4(Context* ctx, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(ip4_hdr)) {
		return;
	}

	const ip4_hdr* ip = reinterpret_cast<const ip4_hdr*>(payload.data());
	uint8_t ihl = ip4_ihl(ip) * 4;

	if (ihl < sizeof(ip4_hdr) || ihl > payload.size()) {
		LOG_D("Invalid IPv4 IHL");
		return;
	}

	uint16_t tot_len = ntohs(ip->tot_len);
	if (tot_len < ihl || tot_len > payload.size()) {
		LOG_D("Invalid IPv4 tot_len");
		return;
	}

	const uint8_t* l4_payload = payload.data() + ihl;
	size_t l4_len = tot_len - ihl;

	/* Drop IP fragments: nstun does not reassemble, and non-first
	 * fragments have no L4 header — parsing them would bypass rules */
	if (ntohs(ip->frag_off) & 0x3FFF) {
		LOG_W("Dropping IPv4 fragment");
		return;
	}

	/* Validate IPv4 header checksum */
	if (compute_checksum(ip, ihl) != 0) {
		LOG_W("Invalid IPv4 header checksum, dropping");
		return;
	}

	if (ip->saddr != ctx->guest_ip4 && ip->saddr != 0) {
		LOG_W("Dropping packet with invalid source IP");
		return;
	}

	/* SSRF gate: reject packets to loopback, broadcast, or INADDR_ANY.
	 * This is the single authoritative check — L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * loopback intentionally (admin-controlled). */
	if (IN_LOOPBACK(ntohl(ip->daddr)) || ip->daddr == htonl(INADDR_ANY) ||
	    ip->daddr == htonl(INADDR_BROADCAST)) {
		LOG_W("Dropping packet destined to loopback, ANY, or broadcast: %s",
		    ip4_to_string(ip->daddr).c_str());
		return;
	}
	uint16_t src_port = 0, dest_port = 0;
	auto l4_span = payload.subspan(ihl, l4_len);
	if (ip->protocol == IPPROTO_TCP && l4_span.size() >= sizeof(tcp_hdr)) {
		const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(l4_span.data());
		src_port = ntohs(tcp->source);
		dest_port = ntohs(tcp->dest);
	} else if (ip->protocol == IPPROTO_UDP && l4_span.size() >= sizeof(udp_hdr)) {
		const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(l4_span.data());
		src_port = ntohs(udp->source);
		dest_port = ntohs(udp->dest);
	}

	if (src_port != 0 && dest_port != 0) {
		LOG_D("IP packet: proto=%u, %s:%u -> %s:%u, len=%zu", ip->protocol,
		    ip4_to_string(ip->saddr).c_str(), src_port, ip4_to_string(ip->daddr).c_str(),
		    dest_port, l4_len);
	} else {
		LOG_D("IP packet: proto=%u, %s -> %s, len=%zu", ip->protocol,
		    ip4_to_string(ip->saddr).c_str(), ip4_to_string(ip->daddr).c_str(), l4_len);
	}

	switch (ip->protocol) {
	case IPPROTO_ICMP:
		handle_icmp4(ctx, ip, payload.subspan(ihl, l4_len));
		break;
	case IPPROTO_UDP:
		handle_udp4(ctx, ip, payload.subspan(ihl, l4_len));
		break;
	case IPPROTO_TCP:
		handle_tcp4(ctx, ip, payload.subspan(ihl, l4_len));
		break;
	default:
		LOG_D("Unknown IPv4 protocol: %u", ip->protocol);
		break;
	}
}

void handle_ip6(Context* ctx, std::span<const uint8_t> payload) {
	if (payload.size() < sizeof(ip6_hdr)) {
		return;
	}

	const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(payload.data());
	uint16_t payload_len = ntohs(ip6->payload_len);

	if (payload_len + sizeof(ip6_hdr) > payload.size()) {
		LOG_D("Invalid IPv6 payload_len");
		return;
	}

	/* Source IP filtering */
	if (memcmp(ip6->saddr, ctx->guest_ip6, 16) != 0) {
		if (IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*)ip6->saddr) ||
		    IN6_IS_ADDR_SITELOCAL((const struct in6_addr*)ip6->saddr)) {
			LOG_D("Dropping IPv6 packet with link/site-local source address: %s",
			    ip6_to_string(ip6->saddr).c_str());
			return;
		} else {
			LOG_W("Dropping IPv6 packet with spoofed source address: %s",
			    ip6_to_string(ip6->saddr).c_str());
			return;
		}
	}

	/* SSRF gate: reject packets to loopback, v4-mapped, link-local, or site-local.
	 * This is the single authoritative check — L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * ::1 intentionally (admin-controlled). */
	if (IN6_IS_ADDR_LOOPBACK((const struct in6_addr*)ip6->daddr)) {
		LOG_D("Dropping IPv6 packet to loopback: %s", ip6_to_string(ip6->daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED((const struct in6_addr*)ip6->daddr)) {
		LOG_D("Dropping IPv6 packet to v4-mapped address (use IPv4 directly): %s",
		    ip6_to_string(ip6->daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*)ip6->daddr) ||
	    IN6_IS_ADDR_SITELOCAL((const struct in6_addr*)ip6->daddr)) {
		LOG_D("Dropping IPv6 packet to link/site-local address: %s",
		    ip6_to_string(ip6->daddr).c_str());
		return;
	}
	/*
	 * Skip IPv6 extension headers to find the actual L4 protocol.
	 *
	 * RFC 8200 §4: Extension headers must be processed in order.
	 * Each header's "Next Header" field identifies what follows.
	 * We only need to find the L4 header, not process the extensions.
	 */
	auto skip_ext_headers = [](int next_header, const uint8_t*& ptr, size_t& rem) -> int {
		constexpr int MAX_EXT = 8; /* Defense: cap chain depth */
		for (int i = 0; i < MAX_EXT; ++i) {
			auto ext_len = [&]() -> ssize_t {
				switch (next_header) {
				case IPPROTO_HOPOPTS: /* Hop-by-Hop */
				case IPPROTO_DSTOPTS: /* Destination Options */
				case IPPROTO_ROUTING: /* Routing */
				case 139:	      /* Host Identity Protocol */
				case 140: {	      /* Shim6 */
					if (rem < 2) return -1;
					size_t len = ((size_t)ptr[1] + 1) * 8;
					return len <= rem ? (ssize_t)len : -1;
				}
				case IPPROTO_FRAGMENT:
					/* nstun does not reassemble fragments. Drop unconditionally
					 * to match IPv4 behavior and prevent L4 port inspection
					 * bypass. */
					return -1;
				case IPPROTO_AH: { /* Authentication Header */
					if (rem < 2) return -1;
					size_t len = ((size_t)ptr[1] + 2) * 4;
					return len <= rem ? (ssize_t)len : -1;
				}
				default:
					return 0;
				}
			}();

			if (ext_len < 0) return -1;	      /* Malformed or unsupported */
			if (ext_len == 0) return next_header; /* Reached L4 */

			next_header = ptr[0]; /* Next Header field */
			ptr += ext_len;
			rem -= ext_len;
		}
		return -1; /* Chain too deep */
	};

	const uint8_t* l4_payload = payload.data() + sizeof(ip6_hdr);
	size_t remaining = payload_len;

	int l4_proto = skip_ext_headers(ip6->next_header, l4_payload, remaining);
	if (l4_proto < 0) {
		LOG_D("Failed to parse IPv6 extension headers");
		return;
	}

	uint16_t src_port = 0, dest_port = 0;
	if (l4_proto == IPPROTO_TCP && remaining >= sizeof(tcp_hdr)) {
		const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(l4_payload);
		src_port = ntohs(tcp->source);
		dest_port = ntohs(tcp->dest);
	} else if (l4_proto == IPPROTO_UDP && remaining >= sizeof(udp_hdr)) {
		const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(l4_payload);
		src_port = ntohs(udp->source);
		dest_port = ntohs(udp->dest);
	}

	if (src_port != 0 && dest_port != 0) {
		LOG_D("IPv6 packet: next_header=%u, %s:%u -> %s:%u, len=%u", l4_proto,
		    ip6_to_string(ip6->saddr).c_str(), src_port, ip6_to_string(ip6->daddr).c_str(),
		    dest_port, payload_len);
	} else {
		LOG_D("IPv6 packet: next_header=%u, %s -> %s, len=%u", l4_proto,
		    ip6_to_string(ip6->saddr).c_str(), ip6_to_string(ip6->daddr).c_str(),
		    payload_len);
	}

	switch (l4_proto) {
	case IPPROTO_ICMPV6:
		handle_icmp6(ctx, ip6, std::span<const uint8_t>(l4_payload, remaining));
		break;
	case IPPROTO_UDP:
		handle_udp6(ctx, ip6, std::span<const uint8_t>(l4_payload, remaining));
		break;
	case IPPROTO_TCP:
		handle_tcp6(ctx, ip6, std::span<const uint8_t>(l4_payload, remaining));
		break;
	default:
		LOG_D("Unknown IPv6 next_header: %u", l4_proto);
		break;
	}
}

}  // namespace nstun
