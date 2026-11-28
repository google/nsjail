#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include <array>
#include <string_view>
#include <vector>

#include "nstun/encap.h"

static std::vector<uint8_t> to_bytes(std::string_view s) {
	return std::vector<uint8_t>(s.begin(), s.end());
}

static void test_parse_socks5_auth_reply() {
	const std::array<uint8_t, 2> valid = {nstun::SOCKS5_VERSION, nstun::SOCKS5_AUTH_NONE};
	assert(nstun::parse_socks5_auth_reply(valid));

	const std::array<uint8_t, 1> short_buf = {nstun::SOCKS5_VERSION};
	assert(!nstun::parse_socks5_auth_reply(short_buf));

	const std::array<uint8_t, 2> bad_ver = {0x04, nstun::SOCKS5_AUTH_NONE};
	assert(!nstun::parse_socks5_auth_reply(bad_ver));

	const std::array<uint8_t, 2> bad_method = {nstun::SOCKS5_VERSION, 0xFF};
	assert(!nstun::parse_socks5_auth_reply(bad_method));
}

static void test_parse_socks5_connect_reply_ipv4() {
	const std::array<uint8_t, 10> valid = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_IPV4,
	    192, 0, 2, 10, 0x1F, 0x90, /* 192.0.2.10:8080 */
	};
	assert(!nstun::parse_socks5_connect_reply(valid, nullptr));

	nstun::Socks5Reply out = {0xAA, 0x11223344, 0x5566};
	assert(nstun::parse_socks5_connect_reply(valid, &out));
	assert(out.atyp == nstun::SOCKS5_ATYP_IPV4);
	uint32_t expected_ip = 0;
	assert(inet_pton(AF_INET, "192.0.2.10", &expected_ip) == 1);
	assert(out.bind_ip4 == expected_ip);
	assert(out.bind_port == htons(8080));

	/* Truncated IPv4 reply must fail without mutating out */
	const std::array<uint8_t, 9> truncated = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_IPV4,
	    192, 0, 2, 10, 0x1F,
	};
	out = {0xAA, 0x11223344, 0x5566};
	assert(!nstun::parse_socks5_connect_reply(truncated, &out));
	assert(out.atyp == 0xAA);
	assert(out.bind_ip4 == 0x11223344);
	assert(out.bind_port == 0x5566);
}

static void test_parse_socks5_connect_reply_ipv6() {
	std::array<uint8_t, 22> valid = {};
	valid[0] = nstun::SOCKS5_VERSION;
	valid[1] = nstun::SOCKS5_REP_SUCCESS;
	valid[2] = 0x00;
	valid[3] = nstun::SOCKS5_ATYP_IPV6;
	valid[20] = 0x01;
	valid[21] = 0xBB; /* port 443 */

	/* Pre-fill with sentinel to verify bind_ip4 is deterministically zeroed */
	nstun::Socks5Reply out = {0xAA, 0xDEADBEEF, 0x5566};
	assert(nstun::parse_socks5_connect_reply(valid, &out));
	assert(out.atyp == nstun::SOCKS5_ATYP_IPV6);
	assert(out.bind_ip4 == 0);
	assert(out.bind_port == htons(443));

	/* Truncated IPv6 reply must fail without mutating out */
	out = {0xAA, 0xDEADBEEF, 0x5566};
	assert(!nstun::parse_socks5_connect_reply(std::span<const uint8_t>(valid.data(), 21), &out));
	assert(out.atyp == 0xAA);
	assert(out.bind_ip4 == 0xDEADBEEF);
	assert(out.bind_port == 0x5566);
}

static void test_parse_socks5_connect_reply_domain() {
	/* 4-byte header + len(3) + "abc" + port(1080 = 0x0438) = 10 bytes */
	const std::array<uint8_t, 10> valid = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_DOMAIN,
	    3, 'a', 'b', 'c', 0x04, 0x38,
	};
	nstun::Socks5Reply out = {0xAA, 0xDEADBEEF, 0x5566};
	assert(nstun::parse_socks5_connect_reply(valid, &out));
	assert(out.atyp == nstun::SOCKS5_ATYP_DOMAIN);
	assert(out.bind_ip4 == 0);
	assert(out.bind_port == htons(1080));

	/* Zero-length domain (7-byte total reply, smaller than sizeof(socks5_req)) */
	const std::array<uint8_t, 7> empty_domain = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_DOMAIN,
	    0, 0x00, 0x50,
	};
	out = {0xAA, 0xDEADBEEF, 0x5566};
	assert(nstun::parse_socks5_connect_reply(empty_domain, &out));
	assert(out.atyp == nstun::SOCKS5_ATYP_DOMAIN);
	assert(out.bind_ip4 == 0);
	assert(out.bind_port == htons(80));

	/* Truncated domain replies (missing len byte, missing port byte) */
	const std::array<uint8_t, 4> no_len = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_DOMAIN,
	};
	const std::array<uint8_t, 9> short_domain = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_DOMAIN,
	    3, 'a', 'b', 'c', 0x04,
	};
	out = {0xAA, 0x11223344, 0x5566};
	assert(!nstun::parse_socks5_connect_reply(no_len, &out));
	assert(!nstun::parse_socks5_connect_reply(short_domain, &out));
	assert(out.atyp == 0xAA);
	assert(out.bind_ip4 == 0x11223344);
	assert(out.bind_port == 0x5566);
}

static void test_parse_socks5_connect_reply_invalid() {
	nstun::Socks5Reply out = {0xAA, 0x11223344, 0x5566};

	/* Unknown ATYP values must be rejected */
	for (uint8_t bad_atyp : {uint8_t{0x00}, uint8_t{0x02}, uint8_t{0xFF}}) {
		const std::array<uint8_t, 10> buf = {
		    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x00, bad_atyp,
		    0, 0, 0, 0, 0, 0,
		};
		assert(!nstun::parse_socks5_connect_reply(buf, &out));
		assert(out.atyp == 0xAA);
		assert(out.bind_ip4 == 0x11223344);
		assert(out.bind_port == 0x5566);
	}

	/* Non-zero RSV byte must be rejected */
	const std::array<uint8_t, 10> bad_rsv = {
	    nstun::SOCKS5_VERSION, nstun::SOCKS5_REP_SUCCESS, 0x01, nstun::SOCKS5_ATYP_IPV4,
	    127, 0, 0, 1, 0x00, 0x50,
	};
	assert(!nstun::parse_socks5_connect_reply(bad_rsv, &out));

	/* Non-success REP and bad version */
	const std::array<uint8_t, 10> bad_rep = {
	    nstun::SOCKS5_VERSION, 0x01, 0x00, nstun::SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50,
	};
	const std::array<uint8_t, 10> bad_ver = {
	    0x04, nstun::SOCKS5_REP_SUCCESS, 0x00, nstun::SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50,
	};
	assert(!nstun::parse_socks5_connect_reply(bad_rep, &out));
	assert(!nstun::parse_socks5_connect_reply(bad_ver, &out));
}

static void test_parse_http_connect_reply() {
	/* Valid 2xx responses */
	assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 200 Connection Established\r\n\r\n")));
	assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.0 200 OK\r\n\r\n")));
	assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 204\r\n\r\n")));
	assert(nstun::parse_http_connect_reply(to_bytes("HTTP/1.1 299")));

	/* Non-2xx and malformed status lines must be rejected */
	for (std::string_view invalid : {
	         std::string_view(""),
	         std::string_view("HTTP/1.1 20"),
	         std::string_view("HTTP/1.1 407 Proxy Auth Required\r\n\r\n"),
	         std::string_view("HTTP/1.1 502 Bad Gateway\r\n\r\n"),
	         std::string_view("HTTP/1.2 200 OK\r\n\r\n"),
	         std::string_view("HTTP/1.X 200 OK\r\n\r\n"),
	         std::string_view("HTTP/1.1!200 OK\r\n\r\n"),
	         std::string_view("HTTP/1.1 2ab OK\r\n\r\n"),
	         std::string_view("HTTP/1.1 20x OK\r\n\r\n"),
	         std::string_view("HTTP/1.1 2000 OK\r\n\r\n"),
	         std::string_view("HTTP/1.1 200OK\r\n\r\n"),
	     }) {
		assert(!nstun::parse_http_connect_reply(to_bytes(invalid)));
	}
}

static void test_find_end_of_headers() {
	assert(nstun::find_end_of_headers(to_bytes("HTTP/1.1 200 OK\r\n\r\nbody")) == 19);
	assert(nstun::find_end_of_headers(to_bytes("HTTP/1.1 200 OK\r\n")) == 0);
	assert(nstun::find_end_of_headers(to_bytes("\r\n\r")) == 0);
}

int main() {
	test_parse_socks5_auth_reply();
	test_parse_socks5_connect_reply_ipv4();
	test_parse_socks5_connect_reply_ipv6();
	test_parse_socks5_connect_reply_domain();
	test_parse_socks5_connect_reply_invalid();
	test_parse_http_connect_reply();
	test_find_end_of_headers();
	return 0;
}
