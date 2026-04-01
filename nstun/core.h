#ifndef NSTUN_CORE_H_
#define NSTUN_CORE_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <compare>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "net_defs.h"
#include "nstun.h"

namespace nstun {

constexpr size_t NSTUN_MAX_FLOWS = 1024;

// Removed MemcmpLess in favor of C++20 operator<=>

struct __attribute__((packed)) FlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t sport;
	uint16_t dport;

	auto operator<=>(const FlowKey4&) const = default;
};

struct __attribute__((packed)) FlowKey6 {
	uint8_t saddr6[16];
	uint8_t daddr6[16];
	uint16_t sport;
	uint16_t dport;

	auto operator<=>(const FlowKey6&) const = default;
};

struct __attribute__((packed)) IcmpFlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t id;

	auto operator<=>(const IcmpFlowKey4&) const = default;
};

struct __attribute__((packed)) IcmpFlowKey6 {
	uint8_t saddr6[16];
	uint8_t daddr6[16];
	uint16_t id;

	auto operator<=>(const IcmpFlowKey6&) const = default;
};

enum class UdpSocks5State {
	ESTABLISHED,	  /* Direct or SOCKS5 ready */
	SOCKS5_GREETING,  /* Sent SOCKS5 greeting, awaiting auth reply */
	SOCKS5_ASSOCIATE, /* Sent UDP ASSOCIATE, awaiting BND addr */
	TCP_CONNECTING,	  /* TCP connect() to SOCKS5 proxy in progress */
};

struct UdpFlow {
	int host_fd = -1;
	int tcp_fd = -1; /* For SOCKS5 UDP associate */
	bool is_ipv6 = false;
	union {
		FlowKey4 key4;
		FlowKey6 key6;
	};
	time_t last_active = 0;
	bool is_redirected = false;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[16];
	};
	uint16_t orig_dest_port = 0;

	bool use_socks5 = false;
	UdpSocks5State state = UdpSocks5State::ESTABLISHED;
	uint32_t bnd_ip = 0;
	uint16_t bnd_port = 0;

	bool host_fd_is_listener = false;
	std::deque<std::vector<uint8_t>> tx_queue;

	~UdpFlow() {
		if (host_fd != -1 && !host_fd_is_listener) ::close(host_fd);
		if (tcp_fd != -1) ::close(tcp_fd);
	}
};

struct TcpFlow;

struct IcmpFlow {
	int host_fd = -1;
	bool is_ipv6 = false;
	union {
		IcmpFlowKey4 key4;
		IcmpFlowKey6 key6;
	};
	time_t last_active = 0;
	bool is_redirected = false;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[16];
	};

	~IcmpFlow() {
		if (host_fd != -1) ::close(host_fd);
	}
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
	std::map<FlowKey4, std::unique_ptr<UdpFlow>> ipv4_udp_flows_by_key;
	std::map<int, UdpFlow*> udp_flows_by_host_fd; // Observer pointer
	std::map<int, UdpFlow*> udp_flows_by_tcp_fd; // Observer pointer

	std::map<FlowKey4, std::unique_ptr<TcpFlow>> ipv4_tcp_flows_by_key;
	std::map<int, TcpFlow*> tcp_flows_by_host_fd; // Observer pointer

	std::map<IcmpFlowKey4, std::unique_ptr<IcmpFlow>> ipv4_icmp_flows_by_key;
	std::map<int, IcmpFlow*> icmp_flows_by_host_fd; // Observer pointer

	/* IPv6 maps (Owning) */
	std::map<FlowKey6, std::unique_ptr<UdpFlow>> ipv6_udp_flows_by_key;
	std::map<FlowKey6, std::unique_ptr<TcpFlow>> ipv6_tcp_flows_by_key;
	std::map<IcmpFlowKey6, std::unique_ptr<IcmpFlow>> ipv6_icmp_flows_by_key;

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



} /* namespace nstun */

#endif /* NSTUN_CORE_H_ */
