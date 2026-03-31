#ifndef NSTUN_SOCKS5_H_
#define NSTUN_SOCKS5_H_

#include <stdint.h>

namespace nstun {

constexpr uint8_t SOCKS5_VERSION = 0x05;

constexpr uint8_t SOCKS5_AUTH_NONE = 0x00;

constexpr uint8_t SOCKS5_CMD_CONNECT = 0x01;
constexpr uint8_t SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

constexpr uint8_t SOCKS5_ATYP_IPV4 = 0x01;
constexpr uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
constexpr uint8_t SOCKS5_ATYP_IPV6 = 0x04;

constexpr uint8_t SOCKS5_REP_SUCCESS = 0x00;

struct __attribute__((packed)) socks5_greeting {
	uint8_t ver;
	uint8_t num_auth;
	uint8_t auth[1];
};

struct __attribute__((packed)) socks5_auth_reply {
	uint8_t ver;
	uint8_t method;
};

struct __attribute__((packed)) socks5_req {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint32_t dst_ip4;
	uint16_t dst_port;
};

struct __attribute__((packed)) socks5_req6 {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t dst_ip6[16];
	uint16_t dst_port;
};

struct __attribute__((packed)) socks5_req_domain {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t domain_len;
};

struct __attribute__((packed)) socks5_udp_hdr {
	uint16_t rsv;
	uint8_t frag;
	uint8_t atyp;
	uint32_t dst_ip4;
	uint16_t dst_port;
};

struct __attribute__((packed)) socks5_udp_hdr6 {
	uint16_t rsv;
	uint8_t frag;
	uint8_t atyp;
	uint8_t dst_ip6[16];
	uint16_t dst_port;
};

struct __attribute__((packed)) socks5_udp_hdr_domain {
	uint16_t rsv;
	uint8_t frag;
	uint8_t atyp;
	uint8_t domain_len;
};

struct __attribute__((packed)) socks5_max_buf {
	uint8_t data[512];
};

} /* namespace nstun */

#endif /* NSTUN_SOCKS5_H_ */