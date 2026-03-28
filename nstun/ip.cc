#include <netinet/in.h>
#include <string.h>

#include "core.h"
#include "logs.h"

namespace nstun {

extern void handle_icmp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len);

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

	if (ip->saddr != ctx->guest_ip && ip->saddr != 0) {
		LOG_D("Dropping packet with invalid source IP");
		return;
	}

	if (IN4_IS_ADDR_LOOPBACK(ip->daddr) || ip->daddr == htonl(INADDR_ANY) ||
	    ip->daddr == htonl(INADDR_BROADCAST)) {
		LOG_W("Dropping packet destined to loopback, ANY, or broadcast");
		return;
	}
	LOG_D("IP packet: proto=%u, %u.%u.%u.%u -> %u.%u.%u.%u, len=%zu", ip->protocol,
	    ((uint8_t*)&ip->saddr)[0], ((uint8_t*)&ip->saddr)[1], ((uint8_t*)&ip->saddr)[2],
	    ((uint8_t*)&ip->saddr)[3], ((uint8_t*)&ip->daddr)[0], ((uint8_t*)&ip->daddr)[1],
	    ((uint8_t*)&ip->daddr)[2], ((uint8_t*)&ip->daddr)[3], l4_len);

	switch (ip->protocol) {
	case NSTUN_IPPROTO_ICMP:
		handle_icmp(ctx, ip, l4_payload, l4_len);
		break;
	case NSTUN_IPPROTO_UDP:
		handle_udp(ctx, ip, l4_payload, l4_len);
		break;
	case NSTUN_IPPROTO_TCP:
		handle_tcp(ctx, ip, l4_payload, l4_len);
		break;
	default:
		LOG_D("Unknown IPv4 protocol: %u", ip->protocol);
		break;
	}
}

}  // namespace nstun