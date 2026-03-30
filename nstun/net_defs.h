#ifndef NSTUN_NET_DEFS_H_
#define NSTUN_NET_DEFS_H_

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace nstun {

constexpr size_t NSTUN_MTU = ((1024 * 64) - 1024);

struct __attribute__((packed)) ip4_hdr {
	uint8_t ihl_version; /* version << 4 | ihl */
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
};

struct __attribute__((packed)) icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t check;
	uint16_t id;
	uint16_t seq;
};

struct __attribute__((packed)) udp_hdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

struct __attribute__((packed)) tcp_hdr {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
	uint8_t res1_doff; /* doff << 4 | res1 */
	uint8_t flags;
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
};

inline uint8_t ip4_version(const ip4_hdr* h) {
	return h->ihl_version >> 4;
}
inline uint8_t ip4_ihl(const ip4_hdr* h) {
	return h->ihl_version & 0x0F;
}
inline void ip4_set_ihl_version(ip4_hdr* h, uint8_t ver, uint8_t ihl) {
	h->ihl_version = (ver << 4) | (ihl & 0x0F);
}

inline uint8_t tcp_doff(const tcp_hdr* h) {
	return h->res1_doff >> 4;
}
inline void tcp_set_doff(tcp_hdr* h, uint8_t doff) {
	h->res1_doff = (doff << 4);
}

constexpr uint8_t NSTUN_IPPROTO_ICMP = 1;
constexpr uint8_t NSTUN_IPPROTO_TCP = 6;
constexpr uint8_t NSTUN_IPPROTO_UDP = 17;

constexpr uint8_t NSTUN_TCP_FLAG_FIN = 0x01;
constexpr uint8_t NSTUN_TCP_FLAG_SYN = 0x02;
constexpr uint8_t NSTUN_TCP_FLAG_RST = 0x04;
constexpr uint8_t NSTUN_TCP_FLAG_PSH = 0x08;
constexpr uint8_t NSTUN_TCP_FLAG_ACK = 0x10;

/* Computes standard internet checksum */
inline uint32_t compute_checksum_part(const void* buf, size_t len, uint32_t sum = 0) {
	const uint8_t* p = static_cast<const uint8_t*>(buf);
	for (size_t i = 0; i < (len & ~1U); i += 2) {
		uint16_t word;
		memcpy(&word, &p[i], 2);
		sum += word;
	}
	if (len & 1) {
		sum += static_cast<uint8_t>(p[len - 1]);
	}
	return sum;
}

inline uint16_t finalize_checksum(uint32_t sum) {
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(~sum);
}

inline uint16_t compute_checksum(const void* buf, size_t len, uint32_t sum = 0) {
	return finalize_checksum(compute_checksum_part(buf, len, sum));
}

inline bool is_loopback_addr(uint32_t addr_net) {
	return (ntohl(addr_net) & 0xFF000000) == 0x7F000000;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
inline struct sockaddr_in init_sockaddr_in(unsigned short family) {
#ifdef sin_zero
	return (struct sockaddr_in){ .sin_family = family, .sin_port = 0, .sin_addr = {0}, .sin_zero = {0} };
#else
	return (struct sockaddr_in){ .sin_family = family, .sin_port = 0, .sin_addr = {0} };
#endif
}
#pragma GCC diagnostic pop

#define INIT_SOCKADDR_IN(family) nstun::init_sockaddr_in(family)

}  // namespace nstun

#endif /* NSTUN_NET_DEFS_H_ */
