#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <span>
#include <string>
#include <vector>

#include "nstun/encap.h"

static std::vector<uint8_t> to_bytes(const char* s) {
	return std::vector<uint8_t>(s, s + strlen(s));
}

int main() {
	/* SOCKS5 auth reply */
	{
		const uint8_t ok[] = {nstun::SOCKS5_VERSION, nstun::SOCKS5_AUTH_NONE};
		const uint8_t bad_ver[] = {0x04, nstun::SOCKS5_AUTH_NONE};
		const uint8_t bad_auth[] = {nstun::SOCKS5_VERSION, 0xFF};
		const uint8_t short_buf[] = {nstun::SOCKS5_VERSION};
		assert(nstun::parse_socks5_auth_reply(ok));
		assert(!nstun::parse_socks5_auth_reply(bad_ver));
		assert(!nstun::parse_socks5_auth_reply(bad_auth));
		assert(!nstun::parse_socks5_auth_reply(short_buf));
	}

	/* SOCKS5 connect reply: valid IPv4 */
	{
		nstun::Socks5Reply out;
		out.atyp = 0xAA;
		out.bind_ip4 = 0xDEADBEEF;
		out.bind_port = 0xBEEF;
		const uint8_t reply4[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_IPV4,
		    192, 0, 2, 10, 0x1F, 0x90};
		assert(nstun::parse_socks5_connect_reply(reply4, &out));
		assert(out.atyp == nstun::SOCKS5_ATYP_IPV4);
		uint32_t expected_ip4 = 0;
		assert(inet_pton(AF_INET, "192.0.2.10", &expected_ip4) == 1);
		assert(out.bind_ip4 == expected_ip4);
		assert(out.bind_port == htons(8080));
	}

	/* SOCKS5 connect reply: valid IPv6 populates bind_ip6 and zeroes bind_ip4 */
	{
		nstun::Socks5Reply out;
		out.bind_ip4 = 0xDEADBEEF;
		uint8_t reply6[22] = {};
		reply6[0] = nstun::SOCKS5_VERSION;
		reply6[1] = nstun::SOCKS5_REP_SUCCESS;
		reply6[2] = 0x00;
		reply6[3] = nstun::SOCKS5_ATYP_IPV6;
		uint8_t expected_ip6[nstun::IPV6_ADDR_LEN] = {};
		assert(inet_pton(AF_INET6, "2001:db8::42", expected_ip6) == 1);
		memcpy(reply6 + 4, expected_ip6, sizeof(expected_ip6));
		uint16_t port_nbo = htons(1080);
		memcpy(reply6 + 20, &port_nbo, sizeof(port_nbo));

		assert(nstun::parse_socks5_connect_reply(reply6, &out));
		assert(out.atyp == nstun::SOCKS5_ATYP_IPV6);
		assert(out.bind_ip4 == 0);
		assert(memcmp(out.bind_ip6, expected_ip6, sizeof(expected_ip6)) == 0);
		assert(out.bind_port == port_nbo);
	}

	/* SOCKS5 connect reply: valid domain, truncated domain, zero-length domain */
	{
		nstun::Socks5Reply out;
		const uint8_t domain_ok[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00,
		    nstun::SOCKS5_ATYP_DOMAIN, 3, 'a', '.', 'b', 0x01, 0xBB};
		assert(nstun::parse_socks5_connect_reply(domain_ok, &out));
		assert(out.atyp == nstun::SOCKS5_ATYP_DOMAIN);
		assert(out.bind_port == htons(443));

		const uint8_t domain_trunc[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00,
		    nstun::SOCKS5_ATYP_DOMAIN, 5, 'a', '.', 'b'};
		assert(!nstun::parse_socks5_connect_reply(domain_trunc, &out));

		const uint8_t domain_empty[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00,
		    nstun::SOCKS5_ATYP_DOMAIN, 0, 0x01, 0xBB};
		assert(!nstun::parse_socks5_connect_reply(domain_empty, &out));
	}

	/* SOCKS5 connect reply: reject non-zero RSV, unknown ATYP, truncated IPv4/IPv6, null out */
	{
		nstun::Socks5Reply out;
		const uint8_t bad_rsv[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x01, nstun::SOCKS5_ATYP_IPV4,
		    127, 0, 0, 1, 0x00, 0x50};
		assert(!nstun::parse_socks5_connect_reply(bad_rsv, &out));

		const uint8_t bad_atyp[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, 0x99, 0, 0, 0, 0, 0, 0};
		assert(!nstun::parse_socks5_connect_reply(bad_atyp, &out));
		assert(out.atyp == 0 && out.bind_ip4 == 0 && out.bind_port == 0);

		const uint8_t trunc4[] = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_IPV4,
		    192, 0, 2};
		assert(!nstun::parse_socks5_connect_reply(trunc4, &out));

		assert(!nstun::parse_socks5_connect_reply(bad_rsv, nullptr));
	}

	/* send_http_connect with intentionally unaligned IPv4 pointer (UBSan alignment check) */
	{
		int fds[2];
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
		alignas(4) uint8_t buf[8] = {};
		uint32_t ip4 = 0;
		assert(inet_pton(AF_INET, "203.0.113.5", &ip4) == 1);
		memcpy(buf + 1, &ip4, sizeof(ip4)); /* intentionally misaligned by +1 */
		assert(nstun::send_http_connect(fds[0], buf + 1, htons(443), false) == 0);
		char recv_buf[256] = {};
		ssize_t n = recv(fds[1], recv_buf, sizeof(recv_buf) - 1, 0);
		assert(n > 0);
		assert(std::string(recv_buf, (size_t)n) ==
		       "CONNECT 203.0.113.5:443 HTTP/1.1\r\nHost: 203.0.113.5:443\r\n\r\n");
		close(fds[0]);
		close(fds[1]);
	}

	/* HTTP CONNECT reply parsing */
	{
		assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 200 Connection Established\r\n\r\n")));
		assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.0 204\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 403 Forbidden\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.X 200 OK\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.1!200 OK\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 2?? OK\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 2000 OK\r\n\r\n")));
		assert(!nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 20")));
	}

	/* find_end_of_headers */
	{
		auto hdr = to_bytes("HTTP/1.1 200 OK\r\n\r\nhello");
		size_t end = nstun::find_end_of_headers(hdr);
		assert(end == 19);
		assert(nstun::find_end_of_headers(to_bytes("HTTP/1.1 200 OK\r\n")) == 0);
	}

	return 0;
}
