#include <assert.h>

#include <arpa/inet.h>
#include <string.h>

#include <span>
#include <vector>

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
	uint32_t orig_dest_ip4 = 0;
	uint8_t orig_dest_ip6[nstun::IPV6_ADDR_LEN] = {};
	uint16_t orig_dest_port = 0;

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
	socks.orig_dest_ip4 = parse_ip4("8.8.8.8");
	socks.orig_dest_port = 53;
	assert(nstun::udp_peer_matches_flow(socks, peer4("198.51.100.9", 1080)));
	assert(!nstun::udp_peer_matches_flow(socks, peer4("198.51.100.10", 1080)));
	assert(!nstun::udp_peer_matches_flow(socks, peer6("2001:db8::9", 1080)));

	/* SOCKS5 UDP inner peer validation (IPv4) */
	auto make_s5_v4 = [](uint16_t rsv, uint8_t frag, uint8_t atyp, const char* ip,
			      uint16_t port, const char* body) {
		std::vector<uint8_t> pkt(sizeof(nstun::socks5_udp_hdr) + strlen(body));
		nstun::socks5_udp_hdr hdr = {};
		hdr.rsv = rsv;
		hdr.frag = frag;
		hdr.atyp = atyp;
		hdr.dst_ip4 = parse_ip4(ip);
		hdr.dst_port = htons(port);
		memcpy(pkt.data(), &hdr, sizeof(hdr));
		memcpy(pkt.data() + sizeof(hdr), body, strlen(body));
		return pkt;
	};
	std::span<const uint8_t> out;
	auto valid_v4 = make_s5_v4(0, 0, nstun::SOCKS5_ATYP_IPV4, "8.8.8.8", 53, "ok");
	assert(nstun::socks5_udp_unwrap_for_flow(socks, valid_v4, &out));
	assert(out.size() == 2 && memcmp(out.data(), "ok", 2) == 0);
	auto empty_v4 = make_s5_v4(0, 0, nstun::SOCKS5_ATYP_IPV4, "8.8.8.8", 53, "");
	assert(nstun::socks5_udp_unwrap_for_flow(socks, empty_v4, &out));
	assert(out.empty());
	assert(!nstun::socks5_udp_unwrap_for_flow(
	    socks, make_s5_v4(0, 0, nstun::SOCKS5_ATYP_IPV4, "1.1.1.1", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(
	    socks, make_s5_v4(0, 0, nstun::SOCKS5_ATYP_IPV4, "8.8.8.8", 5353, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(
	    socks, make_s5_v4(1, 0, nstun::SOCKS5_ATYP_IPV4, "8.8.8.8", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(
	    socks, make_s5_v4(0, 1, nstun::SOCKS5_ATYP_IPV4, "8.8.8.8", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks,
	    std::span<const uint8_t>(valid_v4.data(), sizeof(nstun::socks5_udp_hdr) - 1), &out));
	/* Reject DOMAIN header on numeric IPv4 flow */
	const uint8_t domain_pkt[] = {
	    0, 0, 0, nstun::SOCKS5_ATYP_DOMAIN, 3, 'a', '.', 'b', 0, 53, 'x'};
	assert(!nstun::socks5_udp_unwrap_for_flow(socks, domain_pkt, &out));

	/* SOCKS5 UDP inner peer validation (IPv6) */
	FakeUdpFlow socks6;
	socks6.is_ipv6 = true;
	socks6.use_socks5 = true;
	socks6.bnd_ip = parse_ip4("198.51.100.9");
	socks6.bnd_port = htons(1080);
	assert(inet_pton(AF_INET6, "2001:4860:4860::8888", socks6.orig_dest_ip6) == 1);
	socks6.orig_dest_port = 53;

	auto make_s5_v6 = [](uint16_t rsv, uint8_t frag, uint8_t atyp, const char* ip,
			      uint16_t port, const char* body) {
		std::vector<uint8_t> pkt(sizeof(nstun::socks5_udp_hdr6) + strlen(body));
		nstun::socks5_udp_hdr6 hdr = {};
		hdr.rsv = rsv;
		hdr.frag = frag;
		hdr.atyp = atyp;
		assert(inet_pton(AF_INET6, ip, hdr.dst_ip6) == 1);
		hdr.dst_port = htons(port);
		memcpy(pkt.data(), &hdr, sizeof(hdr));
		memcpy(pkt.data() + sizeof(hdr), body, strlen(body));
		return pkt;
	};
	auto valid_v6 =
	    make_s5_v6(0, 0, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8888", 53, "v6ok");
	assert(nstun::socks5_udp_unwrap_for_flow(socks6, valid_v6, &out));
	assert(out.size() == 4 && memcmp(out.data(), "v6ok", 4) == 0);
	auto empty_v6 = make_s5_v6(0, 0, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8888", 53, "");
	assert(nstun::socks5_udp_unwrap_for_flow(socks6, empty_v6, &out));
	assert(out.empty());
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6,
	    make_s5_v6(0, 0, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8844", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6,
	    make_s5_v6(0, 0, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8888", 54, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6,
	    make_s5_v6(1, 0, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8888", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6,
	    make_s5_v6(0, 1, nstun::SOCKS5_ATYP_IPV6, "2001:4860:4860::8888", 53, "no"), &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6,
	    std::span<const uint8_t>(valid_v6.data(), sizeof(nstun::socks5_udp_hdr6) - 1), &out));
	/* Cross-family mismatch: IPv4 inner header on IPv6 flow and vice versa */
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6, valid_v4, &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks, valid_v6, &out));
	assert(!nstun::socks5_udp_unwrap_for_flow(socks6, domain_pkt, &out));

	return 0;
}
