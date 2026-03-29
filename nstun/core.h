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

struct FlowKey {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;

	bool operator<(const FlowKey& o) const {
		if (saddr != o.saddr) return saddr < o.saddr;
		if (daddr != o.daddr) return daddr < o.daddr;
		if (sport != o.sport) return sport < o.sport;
		return dport < o.dport;
	}
};

struct IcmpFlowKey {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t id;

	bool operator<(const IcmpFlowKey& o) const {
		if (saddr != o.saddr) return saddr < o.saddr;
		if (daddr != o.daddr) return daddr < o.daddr;
		return id < o.id;
	}
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
	FlowKey key;
	time_t last_active;
	bool is_redirected;
	uint32_t orig_dest_ip;
	uint16_t orig_dest_port;

	bool use_socks5;
	UdpSocks5State state;
	uint32_t bnd_ip;
	uint16_t bnd_port;

	std::vector<std::vector<uint8_t>> tx_queue;
};

struct TcpFlow;

struct IcmpFlow {
	int host_fd;
	IcmpFlowKey key;
	time_t last_active;
	bool is_redirected;
	uint32_t orig_dest_ip;
};

struct Context {
	int epoll_fd;
	int tap_fd;
	struct nsj_t* nsj;

	/* IP addresses in network byte order */
	uint32_t guest_ip;
	uint32_t host_ip;

	std::vector<nstun_rule_t> rules;
	std::map<FlowKey, UdpFlow*> udp_flows_by_key;
	std::map<int, UdpFlow*> udp_flows_by_host_fd;
	std::map<int, UdpFlow*> udp_flows_by_tcp_fd; /* For SOCKS5 control socket */

	std::map<FlowKey, TcpFlow*> tcp_flows_by_key;
	std::map<int, TcpFlow*> tcp_flows_by_host_fd;

	std::map<IcmpFlowKey, IcmpFlow*> icmp_flows_by_key;
	std::map<int, IcmpFlow*> icmp_flows_by_host_fd;

	~Context();
};



struct RuleResult {
	nstun_action_t action;
	uint32_t redirect_ip;
	uint16_t redirect_port;
};

RuleResult evaluate_rules(Context* ctx, nstun_proto_t proto, uint32_t src_ip, uint32_t dst_ip,
    uint16_t sport, uint16_t dport);

} /* namespace nstun */

#endif /* NSTUN_CORE_H_ */
