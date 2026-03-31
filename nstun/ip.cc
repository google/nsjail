#include "ip.h"

#include <netinet/in.h>
#include <string.h>

#include "core.h"
#include "icmp.h"
#include "logs.h"
#include "tcp.h"
#include "udp.h"

namespace nstun {
void handle_ip4(Context* ctx, const uint8_t* payload, size_t len) {
	if (len < sizeof(ip4_hdr)) {
		return;
	}

	const ip4_hdr* ip = reinterpret_cast<const ip4_hdr*>(payload);
	uint8_t ihl = ip4_ihl(ip) * 4;

	if (ihl < sizeof(ip4_hdr) || ihl > len) {
		LOG_D("Invalid IPv4 IHL");
		return;
	}

	uint16_t tot_len = ntohs(ip->tot_len);
	if (tot_len < ihl || tot_len > len) {
		LOG_D("Invalid IPv4 tot_len");
		return;
	}

	const uint8_t* l4_payload = payload + ihl;
	size_t l4_len = tot_len - ihl;

	if (ip->saddr != ctx->guest_ip4 && ip->saddr != 0) {
		LOG_D("Dropping packet with invalid source IP");
		return;
	}

	if (IN_LOOPBACK(ntohl(ip->daddr)) || ip->daddr == htonl(INADDR_ANY) ||
	    ip->daddr == htonl(INADDR_BROADCAST)) {
		LOG_W("Dropping packet destined to loopback, ANY, or broadcast");
		return;
	}
	LOG_D("IP packet: proto=%u, %u.%u.%u.%u -> %u.%u.%u.%u, len=%zu", ip->protocol,
	    ((uint8_t*)&ip->saddr)[0], ((uint8_t*)&ip->saddr)[1], ((uint8_t*)&ip->saddr)[2],
	    ((uint8_t*)&ip->saddr)[3], ((uint8_t*)&ip->daddr)[0], ((uint8_t*)&ip->daddr)[1],
	    ((uint8_t*)&ip->daddr)[2], ((uint8_t*)&ip->daddr)[3], l4_len);

	switch (ip->protocol) {
	case IPPROTO_ICMP:
		handle_icmp4(ctx, ip, l4_payload, l4_len);
		break;
	case IPPROTO_UDP:
		handle_udp4(ctx, ip, l4_payload, l4_len);
		break;
	case IPPROTO_TCP:
		handle_tcp4(ctx, ip, l4_payload, l4_len);
		break;
	default:
		LOG_D("Unknown IPv4 protocol: %u", ip->protocol);
		break;
	}
}

void handle_ip6(Context* ctx, const uint8_t* payload, size_t len) {
	if (len < sizeof(ip6_hdr)) {
		return;
	}

	const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(payload);
	uint16_t payload_len = ntohs(ip6->payload_len);

	if (payload_len + sizeof(ip6_hdr) > len) {
		LOG_D("Invalid IPv6 payload_len");
		return;
	}

	LOG_D("IPv6 packet: next_header=%u, len=%u", ip6->next_header, payload_len);

	/* Source IP filtering — only accept packets from the guest IPv6 or link-local */
	if (memcmp(ip6->saddr, ctx->guest_ip6, 16) != 0) {
		static const uint8_t zero16[16] = {};
		bool is_linklocal = IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*)ip6->saddr);
		if (memcmp(ip6->saddr, zero16, 16) != 0 && !is_linklocal) {
			LOG_W("Dropping IPv6 packet with spoofed source address");
			return;
		}
	}

	/* Drop packets destined to loopback or IPv4-mapped addresses (SSRF protection) */
	if (IN6_IS_ADDR_LOOPBACK((const struct in6_addr*)ip6->daddr) ||
	    IN6_IS_ADDR_V4MAPPED((const struct in6_addr*)ip6->daddr)) {
		LOG_W("Dropping IPv6 packet destined to loopback or v4mapped address");
		return;
	}

	const uint8_t* l4_payload = payload + sizeof(ip6_hdr);

	switch (ip6->next_header) {
	case IPPROTO_ICMPV6:
		handle_icmp6(ctx, ip6, l4_payload, payload_len);
		break;
	case IPPROTO_UDP:
		handle_udp6(ctx, ip6, l4_payload, payload_len);
		break;
	case IPPROTO_TCP:
		handle_tcp6(ctx, ip6, l4_payload, payload_len);
		break;
	default:
		LOG_D("Unknown IPv6 next_header: %u", ip6->next_header);
		break;
	}
}

}  // namespace nstun
