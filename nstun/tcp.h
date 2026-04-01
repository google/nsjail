#ifndef NSTUN_TCP_H_
#define NSTUN_TCP_H_

#include <deque>
#include <span>
#include <vector>

#include "core.h"

namespace nstun {

enum class TcpState {
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
};

struct TcpFlow : public Flow {
	int host_fd = -1;
	union {
		FlowKey4 key4;
		FlowKey6 key6;
	};

	TcpState state = TcpState::SYN_SENT;
	ProxyMode proxy_mode = ProxyMode::NONE;
	bool host_eof = false;
	bool guest_eof = false;
	bool fin_sent = false;
	bool syn_acked = false;
	bool fin_acked = false;

	uint32_t seq_to_guest = 0;
	uint32_t ack_from_guest = 0;

	uint32_t seq_from_guest = 0;
	uint32_t ack_to_guest = 0;

	/* Buffer for data from host to guest (not yet ACKed) */
	/* In a real TCP stack, this would handle retransmissions. */
	/* Here, we just queue it to send. */
	std::vector<uint8_t> tx_buffer;
	size_t tx_acked_offset = 0;

	/* Buffer for accumulating proxy handshake responses (SOCKS5/HTTP CONNECT) */
	std::vector<uint8_t> proxy_rx_buffer;

	/* Buffer for data from guest to host to avoid dropping packets on EAGAIN */
	std::vector<uint8_t> rx_buffer;
	size_t rx_sent_offset = 0;

	bool epoll_out_registered = false;
	bool epoll_in_disabled = false;
	bool inbound = false; /* true if flow is HOST_TO_GUEST */
	~TcpFlow() override {
		if (host_fd != -1) ::close(host_fd);
	}

	void handle_host_event(Context* ctx, int fd, uint32_t events) override;
	void periodic_check(Context* ctx, time_t now) override;
	bool is_stale(time_t now) const override;
	void destroy(Context* ctx) override;
};

void tcp_send_packet4(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_send_packet6(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);
void push_to_guest(Context* ctx, TcpFlow* flow);

void handle_tcp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload);
void handle_tcp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload);
void handle_host_tcp(Context* ctx, TcpFlow* flow, uint32_t events);
void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);

} /* namespace nstun */

#endif /* NSTUN_TCP_H_ */