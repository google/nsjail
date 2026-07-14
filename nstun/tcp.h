#ifndef NSTUN_TCP_H_
#define NSTUN_TCP_H_

#include <deque>
#include <span>
#include <vector>

#include "core.h"
#include "tcp_seq.h"

namespace nstun {

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
	bool periodic_check(Context* ctx, time_t now) override;
	bool is_stale(time_t now) const override;
	void destroy(Context* ctx) override;
};

enum class TcpAckUpdate {
	OLD_OR_DUPLICATE,
	ADVANCED,
	FUTURE,
	INVALID_BUFFER,
};

inline bool tcp_ack_allows_payload(TcpAckUpdate update) {
	return update == TcpAckUpdate::OLD_OR_DUPLICATE || update == TcpAckUpdate::ADVANCED;
}

/* Apply an acceptable ACK to the send-side state. Future and internally
 * inconsistent ACKs leave the flow unchanged. */
template <typename Flow>
inline TcpAckUpdate tcp_apply_ack(Flow* flow, uint32_t ack) {
	TcpAckDisposition disposition =
	    tcp_classify_ack(flow->ack_from_guest, flow->seq_to_guest, ack);
	if (disposition == TcpAckDisposition::FUTURE) {
		return TcpAckUpdate::FUTURE;
	}
	if (disposition != TcpAckDisposition::ADVANCING) {
		return TcpAckUpdate::OLD_OR_DUPLICATE;
	}

	size_t sequence_advance = static_cast<uint32_t>(ack - flow->ack_from_guest);
	bool acknowledges_syn = !flow->syn_acked;
	bool acknowledges_fin =
	    flow->fin_sent && !flow->fin_acked && ack == flow->seq_to_guest;
	size_t control_advance =
	    static_cast<size_t>(acknowledges_syn) + static_cast<size_t>(acknowledges_fin);
	if (sequence_advance < control_advance) {
		return TcpAckUpdate::INVALID_BUFFER;
	}
	size_t data_advance = sequence_advance - control_advance;

	if (flow->tx_acked_offset > flow->tx_buffer.size() ||
	    data_advance > flow->tx_buffer.size() - flow->tx_acked_offset) {
		return TcpAckUpdate::INVALID_BUFFER;
	}

	flow->ack_from_guest = ack;
	flow->syn_acked = flow->syn_acked || acknowledges_syn;
	flow->fin_acked = flow->fin_acked || acknowledges_fin;
	flow->tx_acked_offset += data_advance;

	size_t erase_len = flow->tx_acked_offset;
	if (erase_len > 65536 || erase_len == flow->tx_buffer.size()) {
		flow->tx_buffer.erase(
		    flow->tx_buffer.begin(), flow->tx_buffer.begin() + erase_len);
		flow->tx_acked_offset -= erase_len;
	}

	return TcpAckUpdate::ADVANCED;
}

void tcp_send_packet4(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_send_packet6(
    Context* ctx, TcpFlow* flow, uint8_t flags, const uint8_t* data = nullptr, size_t len = 0);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);
/* Returns true if the flow was destroyed. */
bool push_to_guest(Context* ctx, TcpFlow* flow);

void handle_tcp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload);
void handle_tcp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload);
void handle_host_tcp(Context* ctx, TcpFlow* flow, uint32_t events);
void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);

} /* namespace nstun */

#endif /* NSTUN_TCP_H_ */
