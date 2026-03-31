#ifndef NSTUN_CORE_H_
#define NSTUN_CORE_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <vector>

#include "net_defs.h"
#include "nstun.h"

namespace nstun {

constexpr size_t NSTUN_MAX_FLOWS = 1024;

struct MemcmpLess {
	template <typename T>
	bool operator()(const T& a, const T& b) const {
		return memcmp(&a, &b, sizeof(T)) < 0;
	}
};

struct __attribute__((packed)) FlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t sport;
	uint16_t dport;
};

struct __attribute__((packed)) FlowKey6 {
	uint8_t saddr6[16];
	uint8_t daddr6[16];
	uint16_t sport;
	uint16_t dport;
};

struct __attribute__((packed)) IcmpFlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t id;
};

struct __attribute__((packed)) IcmpFlowKey6 {
	uint8_t saddr6[16];
	uint8_t daddr6[16];
	uint16_t id;
};

enum class UdpSocks5State {
	ESTABLISHED,	  /* Direct or SOCKS5 ready */
	SOCKS5_GREETING,  /* Sent SOCKS5 greeting, awaiting auth reply */
	SOCKS5_ASSOCIATE, /* Sent UDP ASSOCIATE, awaiting BND addr */
	TCP_CONNECTING,	  /* TCP connect() to SOCKS5 proxy in progress */
};

struct UdpFlow {
	int host_fd;
	int tcp_fd; /* For SOCKS5 UDP associate */
	bool is_ipv6;
	union {
		FlowKey4 key4;
		FlowKey6 key6;
	};
	time_t last_active;
	bool is_redirected;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[16];
	};
	uint16_t orig_dest_port;

	bool use_socks5;
	UdpSocks5State state;
	uint32_t bnd_ip;
	uint16_t bnd_port;

	bool host_fd_is_listener;
	std::vector<std::vector<uint8_t>> tx_queue;
};

struct TcpFlow;

struct IcmpFlow {
	int host_fd;
	bool is_ipv6;
	union {
		IcmpFlowKey4 key4;
		IcmpFlowKey6 key6;
	};
	time_t last_active;
	bool is_redirected;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[16];
	};
};

struct Context {
	int epoll_fd;
	int tap_fd;
	struct nsj_t* nsj;

	/* IP addresses in network byte order */
	uint32_t guest_ip4;
	uint32_t host_ip4;

	/* IPv6 addresses */
	uint8_t guest_ip6[16];
	uint8_t host_ip6[16];

	std::vector<nstun_rule_t> rules;
	std::map<FlowKey4, UdpFlow*, MemcmpLess> ipv4_udp_flows_by_key;
	std::map<int, UdpFlow*> udp_flows_by_host_fd;
	std::map<int, UdpFlow*> udp_flows_by_tcp_fd; /* For SOCKS5 control socket */

	std::map<FlowKey4, TcpFlow*, MemcmpLess> ipv4_tcp_flows_by_key;
	std::map<int, TcpFlow*> tcp_flows_by_host_fd;

	std::map<IcmpFlowKey4, IcmpFlow*, MemcmpLess> ipv4_icmp_flows_by_key;
	std::map<int, IcmpFlow*> icmp_flows_by_host_fd;

	/* IPv6 maps */
	std::map<FlowKey6, UdpFlow*, MemcmpLess> ipv6_udp_flows_by_key;
	std::map<FlowKey6, TcpFlow*, MemcmpLess> ipv6_tcp_flows_by_key;
	std::map<IcmpFlowKey6, IcmpFlow*, MemcmpLess> ipv6_icmp_flows_by_key;

	std::map<int, nstun_rule_t> host_listener_fd_to_rule;

	~Context();
};

struct RuleResult {
	nstun_action_t action;
	uint32_t redirect_ip4;
	uint16_t redirect_port;
	bool has_redirect_ip6;
	uint8_t redirect_ip6[16];
};

RuleResult evaluate_rules4(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    uint32_t src_ip4, uint32_t dst_ip4, uint16_t sport, uint16_t dport);

RuleResult evaluate_rules6(Context* ctx, nstun_direction_t dir, nstun_proto_t proto,
    const uint8_t* src_ip6, const uint8_t* dst_ip6, uint16_t sport, uint16_t dport);

} /* namespace nstun */

#endif /* NSTUN_CORE_H_ */
