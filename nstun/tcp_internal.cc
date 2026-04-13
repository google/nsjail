#include "tcp_internal.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <algorithm>

#include "encap.h"
#include "logs.h"
#include "macros.h"
#include "util.h"

namespace nstun {

constexpr size_t kMaxHttpHeaderReadSize = 4096;

void handle_socks5_init_host(Context* ctx, TcpFlow* flow, int fd) {
	constexpr size_t expected_len = 2; /* SOCKS5 auth reply is 2 bytes */
	if (flow->c_proxy_rx_len < expected_len) {
		ssize_t recv_len =
		    TEMP_FAILURE_RETRY(recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len,
			expected_len - flow->c_proxy_rx_len, MSG_DONTWAIT));
		if (recv_len == 0) {
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			tcp_rst_and_destroy(ctx, flow);
			return;
		}

		flow->c_proxy_rx_len += recv_len;
	}
	if (flow->c_proxy_rx_len < expected_len) {
		return;
	}

	if (!nstun::parse_socks5_auth_reply(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len)) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_proxy_rx_len = 0;
	flow->tcp_state = TcpState::SOCKS5_CONNECTING;
	LOG_D("Flow %d: SOCKS5_INIT -> SOCKS5_CONNECTING", flow->header.host_fd);

	uint8_t addr_buf[16];
	if (flow->header.is_ipv6) {
		memcpy(addr_buf, flow->header.key6.daddr6, 16);
	} else {
		memcpy(addr_buf, &flow->header.key4.daddr4, 4);
	}
	uint16_t port = flow->header.is_ipv6 ? flow->header.key6.dport : flow->header.key4.dport;

	if (nstun::send_socks5_connect(fd, addr_buf, port, flow->header.is_ipv6) < 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
}

bool handle_socks5_init_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	/* Guest data received during proxy negotiation - buffer it, don't forward yet. */
	if (!append_tcp_rx(flow, data, len)) {
		LOG_E("tcp_rx_buf overflow in handle_socks5_init_guest");
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
	return false;
}

void handle_socks5_connecting_host(Context* ctx, TcpFlow* flow, int fd) {
	size_t avail = PROXY_RX_BUF_CAP - flow->c_proxy_rx_len;
	if (avail == 0) {
		LOG_E("Proxy RX buffer overflow in handle_socks5_connecting_host");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len, avail, MSG_DONTWAIT));
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_proxy_rx_len += recv_len;
	size_t current_len = flow->c_proxy_rx_len;

	if (current_len < 4) {
		return;
	}

	size_t expected_len;
	uint8_t atyp = flow->c_proxy_rx_buf[nstun::SOCKS5_OFF_ATYP];
	switch (atyp) {
	case SOCKS5_ATYP_IPV4:
		expected_len = sizeof(socks5_req);
		break;
	case SOCKS5_ATYP_IPV6:
		expected_len = sizeof(socks5_req6);
		break;
	case SOCKS5_ATYP_DOMAIN:
		if (current_len < sizeof(socks5_req_domain)) {
			return;
		}
		expected_len = sizeof(socks5_req_domain) +
			       flow->c_proxy_rx_buf[nstun::SOCKS5_OFF_DOMAIN_LEN] + sizeof(uint16_t);
		if (expected_len > PROXY_RX_BUF_CAP) {
			LOG_E("SOCKS5 expected length exceeds buffer size");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		break;
	default:
		LOG_W("Unknown SOCKS5 ATYP: %u", atyp);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (current_len < expected_len) {
		return;
	}

	uint8_t rep_ver = flow->c_proxy_rx_buf[nstun::SOCKS5_OFF_VER];
	uint8_t rep_cmd = flow->c_proxy_rx_buf[nstun::SOCKS5_OFF_CMD];
	if (rep_ver != SOCKS5_VERSION || rep_cmd != SOCKS5_REP_SUCCESS) {
		LOG_W("SOCKS5 connection failed: ver=%u rep=%u", rep_ver, rep_cmd);
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (current_len > expected_len) {
		if (!append_tcp_tx(flow, flow->c_proxy_rx_buf.get() + expected_len,
			current_len - expected_len)) {
			LOG_E("tcp_tx_buf overflow in handle_socks5_connecting_host");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
	}
	flow->c_proxy_rx_len = 0;
	flow->tcp_state = TcpState::ESTABLISHED;
	LOG_D("Flow %d: SOCKS5_CONNECTING -> ESTABLISHED", flow->header.host_fd);
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_socks5_connecting_host: failed to send SYN/ACK");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	flow->seq_to_guest++;

	if (flow->c_tcp_tx_len > 0) {
		push_to_guest(ctx, flow);
	}
}

void handle_http_connect_wait_host(Context* ctx, TcpFlow* flow, int fd) {
	size_t end_of_headers = 0;

	size_t avail = PROXY_RX_BUF_CAP - flow->c_proxy_rx_len;
	if (avail == 0) {
		LOG_E("HTTP proxy response too long");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	size_t to_read = std::min(kMaxHttpHeaderReadSize, avail);
	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_proxy_rx_buf.get() + flow->c_proxy_rx_len, to_read, MSG_DONTWAIT));
	if (recv_len == 0) {
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	if (recv_len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tcp_rst_and_destroy(ctx, flow);
		}
		return;
	}

	flow->c_proxy_rx_len += recv_len;

	end_of_headers =
	    nstun::find_end_of_headers(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len);
	if (end_of_headers == 0) {
		if (flow->c_proxy_rx_len >= PROXY_RX_BUF_CAP) {
			LOG_E("HTTP proxy response too long without headers end");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
		return;
	}

	if (!nstun::parse_http_connect_reply(flow->c_proxy_rx_buf.get(), flow->c_proxy_rx_len)) {
		LOG_W("HTTP CONNECT failed: %.*s",
		    static_cast<int>(std::min(end_of_headers, static_cast<size_t>(64))),
		    flow->c_proxy_rx_buf.get());
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	if (flow->c_proxy_rx_len > end_of_headers) {
		if (!append_tcp_tx(flow, flow->c_proxy_rx_buf.get() + end_of_headers,
			flow->c_proxy_rx_len - end_of_headers)) {
			LOG_E("tcp_tx_buf overflow in handle_http_connect_wait_host");
			tcp_rst_and_destroy(ctx, flow);
			return;
		}
	}
	flow->c_proxy_rx_len = 0;

	flow->tcp_state = TcpState::ESTABLISHED;
	LOG_D("Flow %d: HTTP_CONNECT_WAIT -> ESTABLISHED", flow->header.host_fd);
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_SYN | NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_http_connect_wait_host: failed to send SYN/ACK");
		tcp_rst_and_destroy(ctx, flow);
		return;
	}
	flow->seq_to_guest++;

	if (flow->c_tcp_tx_len > 0) {
		push_to_guest(ctx, flow);
	}
}

void handle_data_transfer_host(Context* ctx, TcpFlow* flow, int fd) {
	size_t avail = TCP_TX_BUF_CAP - flow->c_tcp_tx_len;
	if (avail == 0) {
		if (!flow->epoll_in_disabled) {
			flow->epoll_in_disabled = true;
			if (!tcp_update_host_mask(flow)) {
				PLOG_E("tcp_update_host_mask() failed");
				tcp_rst_and_destroy(ctx, flow);
				return;
			}
		}
		return;
	}

	ssize_t recv_len = TEMP_FAILURE_RETRY(
	    recv(fd, flow->c_tcp_tx_buf.get() + flow->c_tcp_tx_len, avail, MSG_DONTWAIT));
	if (recv_len == 0) {
		handle_host_tcp_data_eof(ctx, flow, fd);
		return;
	}
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		tcp_rst_and_destroy(ctx, flow);
		return;
	}

	flow->c_tcp_tx_len += recv_len;

	if (flow->tcp_state != TcpState::SYN_SENT) {
		push_to_guest(ctx, flow);
	}
}

bool handle_data_transfer_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	if (!append_tcp_rx(flow, data, len)) {
		LOG_E("tcp_rx_buf overflow in handle_data_transfer_guest");
		tcp_rst_and_destroy(ctx, flow);
		return true;
	}
	return flush_to_host(ctx, flow);
}

void handle_draining_state_host(Context* ctx, TcpFlow* flow, int fd) {
	uint8_t discard[128];
	ssize_t n = TEMP_FAILURE_RETRY(recv(fd, discard, sizeof(discard), MSG_DONTWAIT));
	if (n == 0) {
		LOG_D("EOF in draining state for fd %d, destroying flow", fd);
		tcp_destroy_flow(ctx, flow);
	} else if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PLOG_W("recv in handle_draining_state_host");
		}
	}
}

bool handle_draining_state_guest(Context* ctx, TcpFlow* flow, const uint8_t* data, size_t len) {
	if (!tcp_send_packet(ctx, flow, NSTUN_TCP_FLAG_ACK)) {
		LOG_W("handle_draining_state_guest: failed to send ACK");
	}
	return false;
}

}  // namespace nstun
