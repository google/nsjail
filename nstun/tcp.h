#ifndef NSTUN_TCP_H_
#define NSTUN_TCP_H_

#include <deque>
#include <vector>

#include "core.h"

namespace nstun {

enum class TcpState {
	CLOSED,
	SYN_SENT,	   /* host connecting */
	SOCKS5_INIT,	   /* sent SOCKS5 greeting */
	SOCKS5_CONNECTING, /* sent SOCKS5 connect request */
	HTTP_CONNECT_INIT, /* sent HTTP CONNECT request */
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK
};

struct TcpFlow {
	int host_fd;
	bool is_ipv6;
	union {
		FlowKey4 key4;
		FlowKey6 key6;
	};

	enum class ProxyMode : uint8_t { NONE, SOCKS5, HTTP_CONNECT };

	TcpState state;
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

	uint16_t guest_window;

	/* Buffer for data from host to guest (not yet ACKed) */
	/* In a real TCP stack, this would handle retransmissions. */
	/* Here, we just queue it to send. */
	std::vector<uint8_t> tx_buffer;
	size_t tx_acked_offset;

	/* Buffer for accumulating proxy handshake responses (SOCKS5/HTTP CONNECT) */
	std::vector<uint8_t> socks5_rx_buffer;

	/* Buffer for data from guest to host to avoid dropping packets on EAGAIN */
	std::vector<uint8_t> rx_buffer;
	size_t rx_sent_offset;

	bool epoll_out_registered;
	bool epoll_in_disabled;
	bool inbound; /* true if flow is HOST_TO_GUEST */
	time_t last_active;
};

void tcp_send_packet4(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_send_packet6(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);
void push_to_guest(Context* ctx, TcpFlow* flow);

void handle_tcp4(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len);
void handle_tcp6(Context* ctx, const ip6_hdr* ip, const uint8_t* payload, size_t len);
void handle_host_tcp(Context* ctx, int fd, uint32_t events);
void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);

} /* namespace nstun */

#endif /* NSTUN_TCP_H_ */