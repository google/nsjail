#ifndef NSTUN_TCP_INTERNAL_H_
#define NSTUN_TCP_INTERNAL_H_

#include <netinet/in.h>
#include <string.h>

#include "tcp.h"

namespace nstun {

bool tcp_update_host_mask(TcpFlow* flow);
void tcp_rst_and_destroy(Context* ctx, TcpFlow* flow);
void handle_host_tcp_data_eof(Context* ctx, TcpFlow* flow, int fd);

static inline bool tcp_send_packet(Context* ctx, const TcpFlow* flow, uint8_t flags,
    const uint8_t* data = nullptr, size_t len = 0) {
	if (flow->header.is_ipv6) {
		return tcp_send_packet6(ctx, flow, flags, data, len);
	} else {
		return tcp_send_packet4(ctx, flow, flags, data, len);
	}
}

void handle_socks5_init_host(Context* ctx, TcpFlow* flow, int fd);
bool handle_socks5_init_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len);
void handle_socks5_connecting_host(Context* ctx, TcpFlow* flow, int fd);
void handle_http_connect_wait_host(Context* ctx, TcpFlow* flow, int fd);
void handle_data_transfer_host(Context* ctx, TcpFlow* flow, int fd);
bool handle_data_transfer_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len);
void handle_draining_state_host(Context* ctx, TcpFlow* flow, int fd);
bool handle_draining_state_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len);

static inline bool append_tcp_rx(TcpFlow* flow, const uint8_t* data, size_t len) {
	if (flow->c_tcp_rx_len + len > TCP_RX_BUF_CAP) {
		return false;
	}
	memcpy(flow->c_tcp_rx_buf.get() + flow->c_tcp_rx_len, data, len);
	flow->c_tcp_rx_len += len;
	return true;
}

static inline bool append_tcp_tx(TcpFlow* flow, const uint8_t* data, size_t len) {
	if (flow->c_tcp_tx_len + len > TCP_TX_BUF_CAP) {
		return false;
	}
	memcpy(flow->c_tcp_tx_buf.get() + flow->c_tcp_tx_len, data, len);
	flow->c_tcp_tx_len += len;
	return true;
}

void push_to_guest(Context* ctx, TcpFlow* flow);
bool flush_to_host(Context* ctx, TcpFlow* flow);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);

} /* namespace nstun */

#endif /* NSTUN_TCP_INTERNAL_H_ */
