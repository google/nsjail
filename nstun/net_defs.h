#ifndef NSTUN_NET_DEFS_H_
#define NSTUN_NET_DEFS_H_

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

namespace nstun {

#pragma pack(push, 1)

struct eth_hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t ethertype;
};

struct arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	uint8_t sha[6];
	uint32_t spa;
	uint8_t tha[6];
	uint32_t tpa;
};

struct ip4_hdr {
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

struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t check;
	uint16_t id;
	uint16_t seq;
};

struct udp_hdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

struct tcp_hdr {
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

#pragma pack(pop)

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

constexpr uint16_t NSTUN_ETH_P_IP = 0x0800;
constexpr uint16_t NSTUN_ETH_P_ARP = 0x0806;
constexpr uint16_t NSTUN_ETH_P_IPV6 = 0x86DD;

constexpr uint16_t NSTUN_ARP_OP_REQUEST = 1;
constexpr uint16_t NSTUN_ARP_OP_REPLY = 2;

constexpr uint8_t NSTUN_IPPROTO_ICMP = 1;
constexpr uint8_t NSTUN_IPPROTO_TCP = 6;
constexpr uint8_t NSTUN_IPPROTO_UDP = 17;

constexpr uint8_t NSTUN_TCP_FLAG_FIN = 0x01;
constexpr uint8_t NSTUN_TCP_FLAG_SYN = 0x02;
constexpr uint8_t NSTUN_TCP_FLAG_RST = 0x04;
constexpr uint8_t NSTUN_TCP_FLAG_PSH = 0x08;
constexpr uint8_t NSTUN_TCP_FLAG_ACK = 0x10;

/* Computes standard internet checksum */
inline uint16_t compute_checksum(const void* buf, size_t len, uint32_t sum = 0) {
	const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buf);
	while (len > 1) {
		sum += *ptr++;
		len -= 2;
	}
	if (len == 1) {
		sum += *reinterpret_cast<const uint8_t*>(ptr);
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(~sum);
}

}  // namespace nstun

#define IN4_IS_ADDR_LOOPBACK(a) ((((uint32_t)(ntohl(a))) & 0xff000000) == 0x7f000000)

#endif	// NSTUN_NET_DEFS_H_