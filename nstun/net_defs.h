#ifndef NSTUN_NET_DEFS_H_
#define NSTUN_NET_DEFS_H_

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* From <linux/in.h>, can't include directly due to conflicts with <netinet/in.h> */
#ifndef IN_LOOPBACK
#define IN_LOOPBACK(a) ((((long int)(a)) & 0xff000000) == 0x7f000000)
#endif

namespace nstun {

constexpr size_t NSTUN_MTU = ((1024 * 64) - 1024);

constexpr size_t IPV4_ADDR_LEN = sizeof(in_addr);
constexpr size_t IPV6_ADDR_LEN = sizeof(in6_addr);

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

struct __attribute__((packed)) ip6_hdr {
	uint32_t vtf; /* version=4, traffic class=8, flow label=20 */
	uint16_t payload_len;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t saddr[16];
	uint8_t daddr[16];
};

struct __attribute__((packed)) icmp4_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t check;
	uint16_t id;
	uint16_t seq;
};

struct __attribute__((packed)) icmp6_hdr {
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

struct __attribute__((packed)) tcp_opt_mss {
	uint8_t kind;
	uint8_t len;
	uint16_t mss;
};

struct __attribute__((packed)) tcp_opt_wscale {
	uint8_t kind;
	uint8_t len;
	uint8_t shift;
};

struct __attribute__((packed)) pseudo_hdr4 {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t len;
};

struct __attribute__((packed)) pseudo_hdr6 {
	uint8_t saddr[16];
	uint8_t daddr[16];
	uint32_t len;
	uint8_t zeros[3];
	uint8_t next_header;
};

inline uint8_t ip_version(const uint8_t* ptr) {
	return ptr[0] >> 4;
}


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

constexpr uint8_t NSTUN_TCP_FLAG_FIN = 0x01;
constexpr uint8_t NSTUN_TCP_FLAG_SYN = 0x02;
constexpr uint8_t NSTUN_TCP_FLAG_RST = 0x04;
constexpr uint8_t NSTUN_TCP_FLAG_PSH = 0x08;
constexpr uint8_t NSTUN_TCP_FLAG_ACK = 0x10;

/* Computes standard internet checksum */
inline uint32_t compute_checksum_part(const void* buf, size_t len, uint32_t sum = 0) {
	const uint8_t* p = static_cast<const uint8_t*>(buf);
	size_t i = 0;

	/* Sum 32 bits at a time, split into 16-bit halves to avoid overflow */
	while (len - i >= 4) {
		uint32_t dword;
		memcpy(&dword, &p[i], sizeof(dword));
		sum += static_cast<uint32_t>(dword & 0xFFFF);
		sum += static_cast<uint32_t>(dword >> 16);
		i += 4;
	}

	/* Sum remaining 16 bits */
	while (len - i >= 2) {
		uint16_t word;
		memcpy(&word, &p[i], sizeof(word));
		sum += word;
		i += 2;
	}

	/* Add remaining 8 bits */
	if (i < len) {
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wmissing-braces"
inline struct sockaddr_in init_sockaddr_in(unsigned short family) {
#ifdef sin_zero
	return (struct sockaddr_in){
	    .sin_family = family, .sin_port = 0, .sin_addr = {0}, .sin_zero = {0}};
#else
	return (struct sockaddr_in){.sin_family = family, .sin_port = 0, .sin_addr = {0}};
#endif
}
inline struct sockaddr_in6 init_sockaddr_in6(unsigned short family) {
	return (struct sockaddr_in6){.sin6_family = family,
	    .sin6_port = 0,
	    .sin6_flowinfo = 0,
	    .sin6_addr = {{{0}}},
	    .sin6_scope_id = 0};
}
#pragma GCC diagnostic pop

#define INIT_SOCKADDR_IN(family) nstun::init_sockaddr_in(family)
#define INIT_SOCKADDR_IN6(family) nstun::init_sockaddr_in6(family)

inline std::string ip4_to_string(uint32_t addr_nbo) {
	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &addr_nbo, buf, sizeof(buf)) == nullptr) {
		return "unknown";
	}
	return buf;
}

inline std::string ip6_to_string(const uint8_t addr[16]) {
	char buf[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)) == nullptr) {
		return "unknown";
	}
	return buf;
}

}  // namespace nstun

#endif /* NSTUN_NET_DEFS_H_ */
