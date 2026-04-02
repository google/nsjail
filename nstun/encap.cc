#include "encap.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

#include "logs.h"
#include "net_defs.h"

namespace nstun {

int send_socks5_greeting(int fd) {
	socks5_greeting greeting = {
	    .ver = SOCKS5_VERSION,
	    .num_auth = 1,
	    .auth = {SOCKS5_AUTH_NONE},
	};
	if (send(fd, &greeting, sizeof(greeting), MSG_NOSIGNAL) != (ssize_t)sizeof(greeting)) {
		return -1;
	}
	return 0;
}

bool parse_socks5_auth_reply(std::span<const uint8_t> data) {
	if (data.size() < 2) return false;
	return data[0] == SOCKS5_VERSION && data[1] == SOCKS5_AUTH_NONE;
}

int send_socks5_connect(int fd, const uint8_t* addr, uint16_t port_nbo, bool is_ipv6) {
	if (is_ipv6) {
		socks5_req6 req = {
		    .ver = SOCKS5_VERSION,
		    .cmd = SOCKS5_CMD_CONNECT,
		    .rsv = 0x00,
		    .atyp = SOCKS5_ATYP_IPV6,
		    .dst_ip6 = {},
		    .dst_port = port_nbo, /* Already in network byte order */
		};
		memcpy(req.dst_ip6, addr, sizeof(req.dst_ip6));
		if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req)) {
			return -1;
		}
		return 0;
	} else {
		socks5_req req = {
		    .ver = SOCKS5_VERSION,
		    .cmd = SOCKS5_CMD_CONNECT,
		    .rsv = 0x00,
		    .atyp = SOCKS5_ATYP_IPV4,
		    .dst_ip4 = 0,
		    .dst_port = port_nbo,
		};
		memcpy(&req.dst_ip4, addr, 4);
		if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req)) {
			return -1;
		}
		return 0;
	}
}

int send_socks5_udp_associate(int fd) {
	socks5_req req = {
	    .ver = SOCKS5_VERSION,
	    .cmd = SOCKS5_CMD_UDP_ASSOCIATE,
	    .rsv = 0x00,
	    .atyp = SOCKS5_ATYP_IPV4,
	    .dst_ip4 = 0,
	    .dst_port = 0,
	};
	if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req)) {
		return -1;
	}
	return 0;
}

bool parse_socks5_connect_reply(std::span<const uint8_t> data, Socks5Reply* out) {
	if (data.size() < 4) return false;

	/* data[0]=ver, data[1]=rep, data[2]=rsv, data[3]=atyp */
	if (data[0] != SOCKS5_VERSION) return false;
	if (data[1] != SOCKS5_REP_SUCCESS) return false;

	out->atyp = data[3];

	if (out->atyp == SOCKS5_ATYP_IPV4) {
		/* Full reply: 4-byte header + 4-byte IPv4 + 2-byte port */
		if (data.size() < sizeof(socks5_req)) return false;
		const auto* reply = reinterpret_cast<const socks5_req*>(data.data());
		memcpy(&out->bind_ip4, &reply->dst_ip4, sizeof(reply->dst_ip4));
		memcpy(&out->bind_port, &reply->dst_port, sizeof(reply->dst_port));
	} else if (out->atyp == SOCKS5_ATYP_IPV6) {
		/* Full reply: 4-byte header + 16-byte IPv6 + 2-byte port */
		if (data.size() < sizeof(socks5_req6)) return false;
		const auto* reply = reinterpret_cast<const socks5_req6*>(data.data());
		memcpy(&out->bind_port, &reply->dst_port, sizeof(reply->dst_port));
	}

	return true;
}

int send_http_connect(int fd, const uint8_t* addr, uint16_t port_nbo, bool is_ipv6) {
	std::string addr_str =
	    is_ipv6 ? ip6_to_string(addr) : ip4_to_string(*(const uint32_t*)addr);
	uint16_t port = ntohs(port_nbo);

	/* Max: "CONNECT [" + 39-char IPv6 + "]:65535 HTTP/1.1\r\nHost: [" + 39 + "]:65535\r\n\r\n"
	 */
	char buf[256];
	int n;
	if (is_ipv6) {
		n = snprintf(buf, sizeof(buf), "CONNECT [%s]:%u HTTP/1.1\r\nHost: [%s]:%u\r\n\r\n",
		    addr_str.c_str(), port, addr_str.c_str(), port);
	} else {
		n = snprintf(buf, sizeof(buf), "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
		    addr_str.c_str(), port, addr_str.c_str(), port);
	}

	if (n <= 0 || n >= (int)sizeof(buf)) return -1;
	if (send(fd, buf, n, MSG_NOSIGNAL) != (ssize_t)n) return -1;
	return 0;
}

size_t find_end_of_headers(const std::vector<uint8_t>& buf) {
	for (size_t i = 0; i + 3 < buf.size(); ++i) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
		    buf[i + 3] == '\n') {
			return i + 4;
		}
	}
	return 0;
}

bool parse_http_connect_reply(const std::vector<uint8_t>& buf) {
	/* Minimum valid response: "HTTP/1.x 2xx" = 12 chars.
	 * We only check the version prefix and status class (2xx). */
	static constexpr std::string_view HTTP_VERSION_PREFIX = "HTTP/1.";
	/* Offset of the first status digit in "HTTP/1.x NNN": H(0)T(1)T(2)P(3)/(4)1(5).(6)x(7)
	 * (8)N(9) */
	static constexpr size_t HTTP_STATUS_DIGIT_OFFSET = 9;
	static constexpr size_t HTTP_RESPONSE_MIN_LEN =
	    HTTP_STATUS_DIGIT_OFFSET + 3; /* digit + two more chars of status */

	if (buf.size() < HTTP_RESPONSE_MIN_LEN) return false;
	if (memcmp(buf.data(), HTTP_VERSION_PREFIX.data(), HTTP_VERSION_PREFIX.size()) != 0)
		return false;
	/* Accept any 2xx status code */
	if (buf[HTTP_STATUS_DIGIT_OFFSET] != '2') return false;
	return true;
}

} /* namespace nstun */
