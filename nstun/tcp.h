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
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK
};

struct TcpFlow {
	int host_fd;
	FlowKey key;

	TcpState state;
	bool use_socks5;
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

	bool epoll_out_registered;
	bool epoll_in_disabled;
	time_t last_active;
};

void tcp_send_packet(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);
void push_to_guest(Context* ctx, TcpFlow* flow);

void handle_tcp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len);
void handle_host_tcp(Context* ctx, int fd, uint32_t events);

} /* namespace nstun */

#endif /* NSTUN_TCP_H_ */