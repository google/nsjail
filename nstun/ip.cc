#include "ip.h"

#include <netinet/in.h>
#include <string.h>

#include "core.h"
#include "icmp.h"
#include "ipparse.h"
#include "logs.h"
#include "tcp.h"
#include "udp.h"

namespace nstun {

void handle_ip4(Context* ctx, std::span<const uint8_t> payload) {
	ByteReader reader(payload);
	ip4_hdr ip = {};
	if (!reader.read_struct(&ip)) {
		return;
	}

	size_t ihl = static_cast<size_t>(ip4_ihl(&ip)) * 4;
	if (ihl < sizeof(ip4_hdr) || ihl > payload.size()) {
		LOG_D("Invalid IPv4 IHL");
		return;
	}

	uint16_t tot_len = ntohs(ip.tot_len);
	if (tot_len < ihl || tot_len > payload.size()) {
		LOG_D("Invalid IPv4 tot_len");
		return;
	}

	auto l4_payload = payload.subspan(ihl, static_cast<size_t>(tot_len) - ihl);

	/* Drop IP fragments: nstun does not reassemble, and non-first
	 * fragments have no L4 header - parsing them would bypass rules */
	if (ntohs(ip.frag_off) & 0x3FFF) {
		LOG_W("Dropping IPv4 fragment");
		return;
	}

	/* Validate IPv4 header checksum */
	if (compute_checksum(payload.data(), ihl) != 0) {
		LOG_W("Invalid IPv4 header checksum, dropping");
		return;
	}

	if (ip.saddr != ctx->guest_ip4 && ip.saddr != 0) {
		LOG_W("Dropping packet with invalid source IP");
		return;
	}

	/* SSRF gate: reject packets to loopback, link-local, broadcast, or INADDR_ANY.
	 * This is the single authoritative check - L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * loopback intentionally (admin-controlled). */
	if (IN_LOOPBACK(ntohl(ip.daddr)) || ip4_is_link_local(ip.daddr) ||
	    ip.daddr == htonl(INADDR_ANY) || ip.daddr == htonl(INADDR_BROADCAST)) {
		LOG_W("Dropping packet destined to loopback, link-local, ANY, or broadcast: %s",
		    ip4_to_string(ip.daddr).c_str());
		return;
	}
	uint16_t src_port = 0, dest_port = 0;
	ByteReader l4_reader(l4_payload);
	if (ip.protocol == IPPROTO_TCP) {
		tcp_hdr tcp = {};
		if (l4_reader.read_struct(&tcp)) {
			src_port = ntohs(tcp.source);
			dest_port = ntohs(tcp.dest);
		}
	} else if (ip.protocol == IPPROTO_UDP) {
		udp_hdr udp = {};
		if (l4_reader.read_struct(&udp)) {
			src_port = ntohs(udp.source);
			dest_port = ntohs(udp.dest);
		}
	}

	if (src_port != 0 && dest_port != 0) {
		LOG_D("IP packet: proto=%u, %s:%u -> %s:%u, len=%zu", ip.protocol,
		    ip4_to_string(ip.saddr).c_str(), src_port, ip4_to_string(ip.daddr).c_str(),
		    dest_port, l4_payload.size());
	} else {
		LOG_D("IP packet: proto=%u, %s -> %s, len=%zu", ip.protocol,
		    ip4_to_string(ip.saddr).c_str(), ip4_to_string(ip.daddr).c_str(),
		    l4_payload.size());
	}

	/* The handlers may copy the original header into an ICMP error, so keep
	 * the pointer into the packet rather than the parsed copy above. */
	const ip4_hdr* ip_header = reinterpret_cast<const ip4_hdr*>(payload.data());
	switch (ip.protocol) {
	case IPPROTO_ICMP:
		handle_icmp4(ctx, ip_header, l4_payload);
		break;
	case IPPROTO_UDP:
		handle_udp4(ctx, ip_header, l4_payload);
		break;
	case IPPROTO_TCP:
		handle_tcp4(ctx, ip_header, l4_payload);
		break;
	default:
		LOG_D("Unknown IPv4 protocol: %u", ip.protocol);
		break;
	}
}

void handle_ip6(Context* ctx, std::span<const uint8_t> payload) {
	ByteReader reader(payload);
	ip6_hdr ip6 = {};
	if (!reader.read_struct(&ip6)) {
		return;
	}

	uint16_t payload_len = ntohs(ip6.payload_len);
	if (payload_len > reader.remaining()) {
		LOG_D("Invalid IPv6 payload_len");
		return;
	}

	/* Source IP filtering */
	if (memcmp(ip6.saddr, ctx->guest_ip6, IPV6_ADDR_LEN) != 0) {
		if (IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*)ip6.saddr) ||
		    IN6_IS_ADDR_SITELOCAL((const struct in6_addr*)ip6.saddr)) {
			LOG_D("Dropping IPv6 packet with link/site-local source address: %s",
			    ip6_to_string(ip6.saddr).c_str());
			return;
		} else {
			LOG_W("Dropping IPv6 packet with spoofed source address: %s",
			    ip6_to_string(ip6.saddr).c_str());
			return;
		}
	}

	/* SSRF gate: reject packets to the unspecified address, loopback, v4-mapped,
	 * local-service, link-local, site-local, or multicast.
	 * This is the single authoritative check - L4 handlers rely on this
	 * and do NOT duplicate it. Redirect rules in policy may still target
	 * ::1 intentionally (admin-controlled). */
	if (IN6_IS_ADDR_UNSPECIFIED((const struct in6_addr*)ip6.daddr)) {
		/* connect() to :: reaches ::1 on Linux, exactly as connect() to 0.0.0.0
		 * reaches 127.0.0.1. Without this the guest would get at host loopback
		 * services; handle_ip4() rejects INADDR_ANY for the same reason. */
		LOG_W("Dropping IPv6 packet to the unspecified address: %s",
		    ip6_to_string(ip6.daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_LOOPBACK((const struct in6_addr*)ip6.daddr)) {
		LOG_D("Dropping IPv6 packet to loopback: %s", ip6_to_string(ip6.daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED((const struct in6_addr*)ip6.daddr)) {
		LOG_D("Dropping IPv6 packet to v4-mapped address (use IPv4 directly): %s",
		    ip6_to_string(ip6.daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_V4COMPAT((const struct in6_addr*)ip6.daddr)) {
		LOG_D("Dropping IPv6 packet to v4-compatible address (deprecated): %s",
		    ip6_to_string(ip6.daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*)ip6.daddr) ||
	    IN6_IS_ADDR_SITELOCAL((const struct in6_addr*)ip6.daddr) ||
	    ip6_is_aws_local_service(ip6.daddr)) {
		LOG_D("Dropping IPv6 packet to link/site-local or AWS local-service address: %s",
		    ip6_to_string(ip6.daddr).c_str());
		return;
	}
	if (IN6_IS_ADDR_MULTICAST((const struct in6_addr*)ip6.daddr)) {
		/* nstun is a TUN (L3) device and joins no groups; forwarding these
		 * would emit guest multicast onto the host's network instead. */
		LOG_D("Dropping IPv6 packet to multicast address: %s",
		    ip6_to_string(ip6.daddr).c_str());
		return;
	}
	/*
	 * Skip IPv6 extension headers to find the actual L4 protocol.
	 *
	 * RFC 8200 §4: Extension headers must be processed in order.
	 * Each header's "Next Header" field identifies what follows.
	 * We only need to find the L4 header, not process the extensions.
	 */
	std::span<const uint8_t> l4_area = reader.rest().first(payload_len);
	ByteReader l4_reader(l4_area);
	int l4_proto = skip_ipv6_ext_headers(ip6.next_header, &l4_reader);
	if (l4_proto < 0) {
		LOG_D("Failed to parse IPv6 extension headers");
		return;
	}

	uint16_t src_port = 0, dest_port = 0;
	ByteReader l4_peek = l4_reader;
	if (l4_proto == IPPROTO_TCP) {
		tcp_hdr tcp = {};
		if (l4_peek.read_struct(&tcp)) {
			src_port = ntohs(tcp.source);
			dest_port = ntohs(tcp.dest);
		}
	} else if (l4_proto == IPPROTO_UDP) {
		udp_hdr udp = {};
		if (l4_peek.read_struct(&udp)) {
			src_port = ntohs(udp.source);
			dest_port = ntohs(udp.dest);
		}
	}

	if (src_port != 0 && dest_port != 0) {
		LOG_D("IPv6 packet: next_header=%u, %s:%u -> %s:%u, len=%u", l4_proto,
		    ip6_to_string(ip6.saddr).c_str(), src_port, ip6_to_string(ip6.daddr).c_str(),
		    dest_port, payload_len);
	} else {
		LOG_D("IPv6 packet: next_header=%u, %s -> %s, len=%u", l4_proto,
		    ip6_to_string(ip6.saddr).c_str(), ip6_to_string(ip6.daddr).c_str(),
		    payload_len);
	}

	/* The handlers may copy the original header into an ICMP error, so keep
	 * the pointer into the packet rather than the parsed copy above. */
	const ip6_hdr* ip6_header = reinterpret_cast<const ip6_hdr*>(payload.data());
	switch (l4_proto) {
	case IPPROTO_ICMPV6:
		handle_icmp6(ctx, ip6_header, l4_reader.rest());
		break;
	case IPPROTO_UDP:
		handle_udp6(ctx, ip6_header, l4_reader.rest());
		break;
	case IPPROTO_TCP:
		handle_tcp6(ctx, ip6_header, l4_reader.rest());
		break;
	default:
		LOG_D("Unknown IPv6 next_header: %u", l4_proto);
		break;
	}
}

}  // namespace nstun
