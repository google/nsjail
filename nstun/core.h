#ifndef NSTUN_CORE_H_
#define NSTUN_CORE_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <compare>
#include <cstddef>
#include <memory>

#include "net_defs.h"
#include "nstun.h"
#include "encap.h"

namespace nstun {

constexpr size_t NSTUN_MAX_FLOWS = 1024;
constexpr size_t NSTUN_MAX_FDS = 2048;
constexpr size_t NSTUN_MAX_RULES = 128;
constexpr size_t UDP_QUEUE_PACKET_MAX = 1500;
constexpr size_t UDP_QUEUE_MAX_PACKETS = 50;
constexpr int VLEN = 64;

constexpr size_t TCP_TX_BUF_CAP = 131072;  /* 128 KB - host->guest */
constexpr size_t TCP_RX_BUF_CAP = 131072;  /* 128 KB - guest->host */
constexpr size_t PROXY_RX_BUF_CAP = 8192;  /* 8 KB  - proxy handshake */

/* Removed MemcmpLess in favor of C++20 operator<=> */

struct __attribute__((packed)) FlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t sport;
	uint16_t dport;
};

struct __attribute__((packed)) FlowKey6 {
	uint8_t saddr6[IPV6_ADDR_LEN];
	uint8_t daddr6[IPV6_ADDR_LEN];
	uint16_t sport;
	uint16_t dport;
};

struct __attribute__((packed)) IcmpFlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t id;
};

struct __attribute__((packed)) IcmpFlowKey6 {
	uint8_t saddr6[IPV6_ADDR_LEN];
	uint8_t daddr6[IPV6_ADDR_LEN];
	uint16_t id;
};

struct Context;

enum class FlowType { TCP, UDP, ICMP };
enum class ProxyMode : uint8_t { NONE, SOCKS5, HTTP_CONNECT };

enum UdpSocks5State {
	UDP_S5_ESTABLISHED,	  /* Direct or SOCKS5 ready */
	UDP_S5_GREETING,  /* Sent SOCKS5 greeting, awaiting auth reply */
	UDP_S5_ASSOCIATE, /* Sent UDP ASSOCIATE, awaiting BND addr */
	UDP_S5_TCP_CONNECTING,	  /* TCP connect() to SOCKS5 proxy in progress */
};

enum class TcpState {
	SYN_SENT,	   /* Host connecting to destination */
	SOCKS5_INIT,	   /* Sent SOCKS5 greeting, awaiting auth reply */
	SOCKS5_CONNECTING, /* Sent SOCKS5 CONNECT request, awaiting response */
	HTTP_CONNECT_WAIT, /* Sent HTTP CONNECT, awaiting proxy 200 reply */
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
};

struct FlowHeader {
	bool active;
	FlowType type;
	time_t last_active;
	bool is_ipv6;
	int host_fd;
	union {
		FlowKey4 key4;
		FlowKey6 key6;
		IcmpFlowKey4 icmp_key4;
		IcmpFlowKey6 icmp_key6;
	};
	bool is_redirected;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[IPV6_ADDR_LEN];
	};
	uint16_t orig_dest_port;
	uint32_t redirect_ip4;
	uint8_t redirect_ip6[IPV6_ADDR_LEN];
	uint16_t redirect_port;
};

struct UdpFlow {
	struct FlowHeader header;

	/* UDP specific */
	int tcp_fd;
	bool use_socks5;
	UdpSocks5State state;
	uint32_t bnd_ip;
	uint16_t bnd_port;
	bool host_fd_is_listener;

	struct {
		uint8_t data[UDP_QUEUE_PACKET_MAX];
		size_t len;
	} c_tx_queue[UDP_QUEUE_MAX_PACKETS];
	size_t c_tx_queue_head;
	size_t c_tx_queue_tail;
	size_t c_tx_queue_count;
};

struct TcpFlow {
	struct FlowHeader header;

	/* TCP specific */
	TcpState tcp_state;
	ProxyMode proxy_mode;
	bool host_eof;
	bool guest_eof;
	bool fin_sent;
	bool syn_acked;
	bool fin_acked;

	uint32_t seq_to_guest;
	uint32_t ack_from_guest;

	uint32_t seq_from_guest;
	uint32_t ack_to_guest;

	size_t tx_acked_offset;
	size_t rx_sent_offset;

	/* Heap-allocated buffers (allocated per active flow, freed via RAII) */
	std::unique_ptr<uint8_t[]> c_tcp_tx_buf;
	size_t c_tcp_tx_len;
	std::unique_ptr<uint8_t[]> c_proxy_rx_buf;
	size_t c_proxy_rx_len;
	std::unique_ptr<uint8_t[]> c_tcp_rx_buf;
	size_t c_tcp_rx_len;

	bool epoll_out_registered;
	bool epoll_in_disabled;
	bool inbound;
};

struct IcmpFlow {
	struct FlowHeader header;
};


struct Context {
	int tap_fd;
	struct nsj_t* nsj;

	/* IP addresses in network byte order */
	uint32_t guest_ip4;
	uint32_t host_ip4;

	/* IPv6 addresses */
	uint8_t guest_ip6[IPV6_ADDR_LEN];
	uint8_t host_ip6[IPV6_ADDR_LEN];


	nstun_rule_t c_rules[NSTUN_MAX_RULES];
	size_t c_rules_count;

	TcpFlow c_ipv4_tcp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv4_tcp_flows;
	UdpFlow c_ipv4_udp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv4_udp_flows;
	UdpFlow c_ipv6_udp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv6_udp_flows;
	TcpFlow c_ipv6_tcp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv6_tcp_flows;
	IcmpFlow c_ipv4_icmp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv4_icmp_flows;
	IcmpFlow c_ipv6_icmp_flows[NSTUN_MAX_FLOWS];
	size_t num_c_ipv6_icmp_flows;
	struct {
		int fd;
		nstun_rule_t rule;
	} c_host_listener_rules[NSTUN_MAX_RULES];
	size_t num_c_host_listener_rules;

	/* Buffer for TUN frames, moved from TLS to avoid stack/TLS pressure */
	uint8_t tun_buf[NSTUN_MTU + 4];

	/* Buffers for recvmmsg, moved from TLS to avoid stack/TLS pressure */
	struct mmsghdr recvmmsg_msgs[VLEN];
	struct iovec recvmmsg_iovecs[VLEN];
	alignas(std::max_align_t) uint8_t recvmmsg_bufs[VLEN][NSTUN_MTU];
	struct sockaddr_storage recvmmsg_addrs[VLEN];
	bool recvmmsg_initialized;

	/* Buffer for SOCKS5 UDP control channel reads */
	socks5_max_buf udp_socks5_buf;

	/* Specific lookup tables for type safety */
	TcpFlow* c_tcp_flows_by_fd[NSTUN_MAX_FDS] = {};
	UdpFlow* c_udp_flows_by_fd[NSTUN_MAX_FDS] = {};
	IcmpFlow* c_icmp_flows_by_fd[NSTUN_MAX_FDS] = {};

};

void handle_host_events(Context* ctx, int fd, uint32_t events);
void host_callback(int fd, uint32_t events, void* data);

struct RuleResult {
	nstun_action_t action;
	uint32_t redirect_ip4;
	uint16_t redirect_port;
	bool has_redirect_ip6;
	uint8_t redirect_ip6[IPV6_ADDR_LEN];
};

inline TcpFlow* get_tcp_flow_by_fd(const Context* ctx, int fd) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return nullptr;
	}
	return ctx->c_tcp_flows_by_fd[fd];
}

inline bool set_tcp_flow_by_fd(Context* ctx, int fd, TcpFlow* flow) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return false;
	}
	ctx->c_tcp_flows_by_fd[fd] = flow;
	return true;
}

inline UdpFlow* get_udp_flow_by_fd(const Context* ctx, int fd) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return nullptr;
	}
	return ctx->c_udp_flows_by_fd[fd];
}

inline bool set_udp_flow_by_fd(Context* ctx, int fd, UdpFlow* flow) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return false;
	}
	ctx->c_udp_flows_by_fd[fd] = flow;
	return true;
}

inline IcmpFlow* get_icmp_flow_by_fd(const Context* ctx, int fd) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return nullptr;
	}
	return ctx->c_icmp_flows_by_fd[fd];
}

inline bool set_icmp_flow_by_fd(Context* ctx, int fd, IcmpFlow* flow) {
	if (fd < 0 || fd >= (int)NSTUN_MAX_FDS) {
		return false;
	}
	ctx->c_icmp_flows_by_fd[fd] = flow;
	return true;
}

} /* namespace nstun */

#endif /* NSTUN_CORE_H_ */
