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

	auto operator<=> (const FlowKey4&) const = default;
};

struct __attribute__((packed)) FlowKey6 {
	uint8_t saddr6[IPV6_ADDR_LEN];
	uint8_t daddr6[IPV6_ADDR_LEN];
	uint16_t sport;
	uint16_t dport;

	auto operator<=> (const FlowKey6&) const = default;
};

struct __attribute__((packed)) IcmpFlowKey4 {
	uint32_t saddr4;
	uint32_t daddr4;
	uint16_t id;

	auto operator<=> (const IcmpFlowKey4&) const = default;
};

struct __attribute__((packed)) IcmpFlowKey6 {
	uint8_t saddr6[IPV6_ADDR_LEN];
	uint8_t daddr6[IPV6_ADDR_LEN];
	uint16_t id;

	auto operator<=> (const IcmpFlowKey6&) const = default;
};

struct Context;

class Flow {
public:
	time_t last_active = 0;
	bool is_ipv6 = false;

	virtual ~Flow() = default;
	virtual void handle_host_event(Context* ctx, int fd, uint32_t events) = 0;
	virtual void periodic_check(Context* ctx, time_t now) {}
	virtual bool is_stale(time_t now) const = 0;
	virtual void destroy(Context* ctx) = 0;
};

enum class ProxyMode : uint8_t { NONE, SOCKS5, HTTP_CONNECT };

enum class UdpSocks5State {
	ESTABLISHED,	  /* Direct or SOCKS5 ready */
	SOCKS5_GREETING,  /* Sent SOCKS5 greeting, awaiting auth reply */
	SOCKS5_ASSOCIATE, /* Sent UDP ASSOCIATE, awaiting BND addr */
	TCP_CONNECTING,	  /* TCP connect() to SOCKS5 proxy in progress */
};

struct UdpFlow : public Flow {
	int host_fd = -1;
	int tcp_fd = -1; /* For SOCKS5 UDP associate */
	union {
		FlowKey4 key4;
		FlowKey6 key6;
	};
	bool is_redirected = false;
	/*
	 * Original destination (before redirect/SOCKS5 rewrite).
	 * Used when forwarding host replies back to the guest.
	 */
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[16];
	};
	uint16_t orig_dest_port = 0;

	/*
	 * Redirect destination - stored at flow creation so the forwarding
	 * path never needs to re-evaluate the rule. For SOCKS5 flows this
	 * is the proxy address; for plain REDIRECT rules it is the target.
	 */
	uint32_t redirect_ip4 = 0;
	uint8_t  redirect_ip6[IPV6_ADDR_LEN] = {};
	uint16_t redirect_port = 0;

	bool use_socks5 = false;
	UdpSocks5State state = UdpSocks5State::ESTABLISHED;
	uint32_t bnd_ip = 0;
	uint16_t bnd_port = 0;

	bool host_fd_is_listener = false;
	std::deque<std::vector<uint8_t>> tx_queue;

	~UdpFlow() override {
		if (host_fd != -1 && !host_fd_is_listener) ::close(host_fd);
		if (tcp_fd != -1) ::close(tcp_fd);
	}

	void handle_host_event(Context* ctx, int fd, uint32_t events) override;
	bool is_stale(time_t now) const override;
	void destroy(Context* ctx) override;
};

struct TcpFlow;

struct IcmpFlow : public Flow {
	int host_fd = -1;
	union {
		IcmpFlowKey4 key4;
		IcmpFlowKey6 key6;
	};
	bool is_redirected = false;
	union {
		uint32_t orig_dest_ip4;
		uint8_t orig_dest_ip6[IPV6_ADDR_LEN];
	};

	~IcmpFlow() override {
		if (host_fd != -1) ::close(host_fd);
	}

	void handle_host_event(Context* ctx, int fd, uint32_t events) override;
	bool is_stale(time_t now) const override;
	void destroy(Context* ctx) override;
};

struct Context {
	int epoll_fd;
	int tap_fd;
	struct nsj_t* nsj;

	/* IP addresses in network byte order */
	uint32_t guest_ip4;
	uint32_t host_ip4;

	/* IPv6 addresses */
	uint8_t guest_ip6[IPV6_ADDR_LEN];
	uint8_t host_ip6[IPV6_ADDR_LEN];

	std::vector<nstun_rule_t> rules;
	std::map<FlowKey4, std::unique_ptr<UdpFlow>> ipv4_udp_flows_by_key;
	std::map<FlowKey4, std::unique_ptr<TcpFlow>> ipv4_tcp_flows_by_key;
	std::map<IcmpFlowKey4, std::unique_ptr<IcmpFlow>> ipv4_icmp_flows_by_key;

	/* Unified host mapping for all encapsulated flows */
	std::map<int, Flow*> flows_by_fd; // Observer pointer

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
	uint8_t redirect_ip6[IPV6_ADDR_LEN];
};



} /* namespace nstun */

#endif /* NSTUN_CORE_H_ */
