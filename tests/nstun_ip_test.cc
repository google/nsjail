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

void handle_udp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {
	++udp4_calls;
}
void handle_udp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}
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

int main() {
	assert(!nstun::ip4_is_link_local(parse_ip4("169.253.255.255")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.0.0")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.169.254")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.255.255")));
	assert(!nstun::ip4_is_link_local(parse_ip4("169.255.0.0")));
	assert(!nstun::ip4_is_link_local(parse_ip4("127.0.0.1")));
	assert(!nstun::ip4_is_link_local(parse_ip4("10.0.0.1")));

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
	assert(dispatch_udp4(ctx, ctx->guest_ip4) == 1);
	assert(dispatch_udp4(ctx, parse_ip4("10.255.255.3")) == 0);
	assert(dispatch_udp4(ctx, htonl(INADDR_ANY)) == 0);
	return 0;
}
