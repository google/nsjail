#include <assert.h>

#include <arpa/inet.h>
#include <stdint.h>

#include <array>
#include <span>

#include "logs.h"
#include "nstun/icmp.h"
#include "nstun/ip.h"
#include "nstun/net_defs.h"
#include "nstun/tcp.h"
#include "nstun/udp.h"

namespace logs {

void logMsg(enum llevel_t, const char*, int, bool, const char*, ...) {}
enum llevel_t getLogLevel() { return ERROR; }

}  // namespace logs

namespace nstun {

static int udp4_calls = 0;
static int udp6_calls = 0;

void handle_udp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {
	++udp4_calls;
}
void handle_udp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {
	++udp6_calls;
}
void handle_tcp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {}
void handle_tcp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}
void handle_icmp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {}
void handle_icmp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}

}  // namespace nstun

static uint32_t parse_ip4(const char* str) {
	uint32_t addr;
	assert(inet_pton(AF_INET, str, &addr) == 1);
	return addr;
}

static bool ip6_is_aws_local_service(const char* str) {
	std::array<uint8_t, 16> addr = {};
	assert(inet_pton(AF_INET6, str, addr.data()) == 1);
	return nstun::ip6_is_aws_local_service(addr.data());
}

static sockaddr_storage peer4(const char* ip) {
	sockaddr_storage storage = {};
	auto* addr = reinterpret_cast<sockaddr_in*>(&storage);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = parse_ip4(ip);
	return storage;
}

static sockaddr_storage peer6(const char* ip) {
	sockaddr_storage storage = {};
	auto* addr = reinterpret_cast<sockaddr_in6*>(&storage);
	addr->sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &addr->sin6_addr) == 1);
	return storage;
}

static std::array<uint8_t, sizeof(nstun::ip4_hdr) + sizeof(nstun::udp_hdr)> make_udp4_packet(
    uint32_t source) {
	std::array<uint8_t, sizeof(nstun::ip4_hdr) + sizeof(nstun::udp_hdr)> packet{};
	auto* ip = reinterpret_cast<nstun::ip4_hdr*>(packet.data());
	auto* udp = reinterpret_cast<nstun::udp_hdr*>(packet.data() + sizeof(*ip));
	nstun::ip4_set_ihl_version(ip, 4, 5);
	ip->tot_len = htons(packet.size());
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = source;
	ip->daddr = parse_ip4("203.0.113.10");
	udp->source = htons(12345);
	udp->dest = htons(443);
	udp->len = htons(sizeof(*udp));
	ip->check = nstun::compute_checksum(ip, sizeof(*ip));
	assert(nstun::compute_checksum(ip, sizeof(*ip)) == 0);
	return packet;
}

static int dispatch_udp4(nstun::Context* ctx, uint32_t source) {
	nstun::udp4_calls = 0;
	auto packet = make_udp4_packet(source);
	nstun::handle_ip4(ctx, packet);
	return nstun::udp4_calls;
}

static uint16_t checksum16(const void* data, size_t len) {
	const uint16_t* p = reinterpret_cast<const uint16_t*>(data);
	uint32_t sum = 0;
	for (size_t i = 0; i < len / 2; i++) sum += p[i];
	if (len & 1) sum += reinterpret_cast<const uint8_t*>(data)[len - 1];
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	return static_cast<uint16_t>(~sum);
}

static std::array<uint8_t, sizeof(nstun::ip6_hdr) + sizeof(nstun::udp_hdr)> make_udp6_packet(
    const uint8_t* source) {
	std::array<uint8_t, sizeof(nstun::ip6_hdr) + sizeof(nstun::udp_hdr)> packet{};
	auto* ip6 = reinterpret_cast<nstun::ip6_hdr*>(packet.data());
	auto* udp = reinterpret_cast<nstun::udp_hdr*>(packet.data() + sizeof(*ip6));
	ip6->vtf = htonl(6u << 28);
	ip6->payload_len = htons(sizeof(*udp));
	ip6->next_header = IPPROTO_UDP;
	ip6->hop_limit = 64;
	memcpy(ip6->saddr, source, 16);
	assert(inet_pton(AF_INET6, "2001:db8::10", ip6->daddr) == 1);
	udp->source = htons(12345);
	udp->dest = htons(443);
	udp->len = htons(sizeof(*udp));
	/* IPv6 UDP checksum is mandatory: compute it over the pseudo-header. */
	struct {
		uint8_t src[16];
		uint8_t dst[16];
		uint32_t len;
		uint8_t zero[3];
		uint8_t next;
	} __attribute__((packed)) pseudo{};
	memcpy(pseudo.src, ip6->saddr, 16);
	memcpy(pseudo.dst, ip6->daddr, 16);
	pseudo.len = htonl(sizeof(*udp));
	pseudo.next = IPPROTO_UDP;
	uint8_t buf[sizeof(pseudo) + sizeof(*udp)];
	memcpy(buf, &pseudo, sizeof(pseudo));
	memcpy(buf + sizeof(pseudo), udp, sizeof(*udp));
	udp->check = checksum16(buf, sizeof(buf));
	return packet;
}

static int dispatch_udp6(nstun::Context* ctx, const uint8_t* source) {
	nstun::udp6_calls = 0;
	auto packet = make_udp6_packet(source);
	nstun::handle_ip6(ctx, packet);
	return nstun::udp6_calls;
}

int main() {
	assert(!nstun::ip4_is_link_local(parse_ip4("169.253.255.255")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.0.0")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.169.254")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.255.255")));
	assert(!nstun::ip4_is_link_local(parse_ip4("169.255.0.0")));
	assert(!nstun::ip4_is_link_local(parse_ip4("127.0.0.1")));
	assert(!nstun::ip4_is_link_local(parse_ip4("10.0.0.1")));

	assert(!nstun::ip4_is_multicast(parse_ip4("223.255.255.255")));
	assert(nstun::ip4_is_multicast(parse_ip4("224.0.0.0")));
	assert(nstun::ip4_is_multicast(parse_ip4("224.0.0.251")));
	assert(nstun::ip4_is_multicast(parse_ip4("239.255.255.250")));
	assert(nstun::ip4_is_multicast(parse_ip4("239.255.255.255")));
	assert(!nstun::ip4_is_multicast(parse_ip4("240.0.0.0")));
	assert(!nstun::ip4_is_multicast(parse_ip4("10.0.0.1")));
	assert(!nstun::ip4_is_multicast(parse_ip4("127.0.0.1")));

	assert(!ip6_is_aws_local_service("fd00:ec1:ffff:ffff:ffff:ffff:ffff:ffff"));
	assert(ip6_is_aws_local_service("fd00:ec2::"));
	assert(ip6_is_aws_local_service("fd00:ec2::254"));
	assert(ip6_is_aws_local_service("fd00:ec2:ffff:ffff:ffff:ffff:ffff:ffff"));
	assert(!ip6_is_aws_local_service("fd00:ec3::"));
	assert(!ip6_is_aws_local_service("fc00::1"));
	assert(!ip6_is_aws_local_service("fe80::1"));

	uint32_t expected4 = parse_ip4("203.0.113.10");
	assert(nstun::sockaddr_matches_ip4(peer4("203.0.113.10"), expected4));
	assert(!nstun::sockaddr_matches_ip4(peer4("203.0.113.11"), expected4));
	assert(!nstun::sockaddr_matches_ip4(peer6("2001:db8::10"), expected4));

	std::array<uint8_t, 16> expected6 = {};
	assert(inet_pton(AF_INET6, "2001:db8::10", expected6.data()) == 1);
	assert(nstun::sockaddr_matches_ip6(peer6("2001:db8::10"), expected6.data()));
	assert(!nstun::sockaddr_matches_ip6(peer6("2001:db8::11"), expected6.data()));
	assert(!nstun::sockaddr_matches_ip6(peer4("203.0.113.10"), expected6.data()));

	/* An nstun guest may retain CAP_NET_RAW. Source validation must therefore
	 * reject the IPv4 unspecified address rather than treating it as trusted. */
	auto* ctx = new nstun::Context{};
	ctx->guest_ip4 = parse_ip4("10.255.255.2");
	ctx->ip4_configured = true;
	assert(dispatch_udp4(ctx, ctx->guest_ip4) == 1);
	assert(dispatch_udp4(ctx, parse_ip4("10.255.255.3")) == 0);
	assert(dispatch_udp4(ctx, htonl(INADDR_ANY)) == 0);

	/* Regression for "nstun accepts traffic on unconfigured IP families":
	 * when IPv4 is left unconfigured (empty user_net.ip4), Context is
	 * value-initialized so guest_ip4 defaults to 0.0.0.0. A guest sending
	 * packets FROM 0.0.0.0 must not be treated as trusted merely because it
	 * coincidentally matches the unconfigured default. */
	{
		auto* unconfigured_ctx = new nstun::Context{};
		assert(unconfigured_ctx->ip4_configured == false);
		assert(unconfigured_ctx->guest_ip4 == 0);
		assert(dispatch_udp4(unconfigured_ctx, htonl(INADDR_ANY)) == 0);
	}

	/* Same class of bug, IPv6 side: when IPv6 is left unconfigured,
	 * guest_ip6 defaults to all-zero (::). A guest sending packets FROM ::
	 * must not slip through (memcmp(src, guest_ip6, ...) == 0 must not be
	 * treated as "matches configured guest address"). */
	{
		auto* unconfigured_ctx = new nstun::Context{};
		assert(unconfigured_ctx->ip6_configured == false);
		uint8_t unspecified6[16] = {};
		assert(dispatch_udp6(unconfigured_ctx, unspecified6) == 0);
	}

	/* Properly configured IPv6 guest addresses must still be accepted. */
	{
		auto* ctx6 = new nstun::Context{};
		assert(inet_pton(AF_INET6, "2001:db8::2", ctx6->guest_ip6) == 1);
		ctx6->ip6_configured = true;
		assert(dispatch_udp6(ctx6, ctx6->guest_ip6) == 1);
		uint8_t wrong_src[16] = {};
		assert(inet_pton(AF_INET6, "2001:db8::3", wrong_src) == 1);
		assert(dispatch_udp6(ctx6, wrong_src) == 0);
		uint8_t unspecified6[16] = {};
		assert(dispatch_udp6(ctx6, unspecified6) == 0);
	}

	return 0;
}
