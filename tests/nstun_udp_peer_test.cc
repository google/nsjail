#include <assert.h>

#include <arpa/inet.h>
#include <string.h>

#include "nstun/udp_peer.h"

struct FakeUdpFlow {
	bool is_ipv6 = false;
	bool is_redirected = false;
	bool use_socks5 = false;
	union {
		nstun::FlowKey4 key4;
		nstun::FlowKey6 key6;
	};
	uint32_t redirect_ip4 = 0;
	uint8_t redirect_ip6[nstun::IPV6_ADDR_LEN] = {};
	uint16_t redirect_port = 0;
	uint32_t bnd_ip = 0;
	uint16_t bnd_port = 0;

	FakeUdpFlow() : key4{} {}
};

static uint32_t parse_ip4(const char* str) {
	uint32_t addr;
	assert(inet_pton(AF_INET, str, &addr) == 1);
	return addr;
}

static sockaddr_storage peer4(const char* ip, uint16_t port) {
	sockaddr_storage storage = {};
	auto* addr = reinterpret_cast<sockaddr_in*>(&storage);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = parse_ip4(ip);
	addr->sin_port = htons(port);
	return storage;
}

static sockaddr_storage peer6(const char* ip, uint16_t port) {
	sockaddr_storage storage = {};
	auto* addr = reinterpret_cast<sockaddr_in6*>(&storage);
	addr->sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &addr->sin6_addr) == 1);
	addr->sin6_port = htons(port);
	return storage;
}

int main() {
	FakeUdpFlow flow4;
	flow4.key4.daddr4 = parse_ip4("203.0.113.10");
	flow4.key4.dport = htons(53);
	assert(nstun::udp_peer_matches_flow(flow4, peer4("203.0.113.10", 53)));
	assert(!nstun::udp_peer_matches_flow(flow4, peer4("203.0.113.11", 53)));
	assert(!nstun::udp_peer_matches_flow(flow4, peer4("203.0.113.10", 54)));

	flow4.is_redirected = true;
	flow4.redirect_ip4 = parse_ip4("192.0.2.20");
	flow4.redirect_port = 5353;
	assert(nstun::udp_peer_matches_flow(flow4, peer4("192.0.2.20", 5353)));
	assert(!nstun::udp_peer_matches_flow(flow4, peer4("203.0.113.10", 53)));

	FakeUdpFlow flow6;
	flow6.is_ipv6 = true;
	memset(&flow6.key6, 0, sizeof(flow6.key6));
	assert(inet_pton(AF_INET6, "2001:db8::10", flow6.key6.daddr6) == 1);
	flow6.key6.dport = htons(443);
	assert(nstun::udp_peer_matches_flow(flow6, peer6("2001:db8::10", 443)));
	assert(!nstun::udp_peer_matches_flow(flow6, peer6("2001:db8::11", 443)));

	flow6.is_redirected = true;
	assert(inet_pton(AF_INET6, "2001:db8::20", flow6.redirect_ip6) == 1);
	flow6.redirect_port = 8443;
	assert(nstun::udp_peer_matches_flow(flow6, peer6("2001:db8::20", 8443)));
	assert(!nstun::udp_peer_matches_flow(flow6, peer6("2001:db8::10", 443)));

	FakeUdpFlow socks;
	socks.use_socks5 = true;
	socks.bnd_ip = parse_ip4("198.51.100.9");
	socks.bnd_port = htons(1080);
	assert(nstun::udp_peer_matches_flow(socks, peer4("198.51.100.9", 1080)));
	assert(!nstun::udp_peer_matches_flow(socks, peer4("198.51.100.10", 1080)));
	assert(!nstun::udp_peer_matches_flow(socks, peer6("2001:db8::9", 1080)));

	return 0;
}
