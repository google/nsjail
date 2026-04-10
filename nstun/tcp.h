#ifndef NSTUN_TCP_H_
#define NSTUN_TCP_H_

#include "core.h"

namespace nstun {

void handle_host_tcp_event(Context* ctx, TcpFlow* flow, int fd, uint32_t events);
void tcp_periodic_check(Context* ctx, TcpFlow* flow, time_t now);
bool is_stale_tcp(const TcpFlow* flow, time_t now);

bool tcp_send_packet4(Context* ctx, const TcpFlow* flow, uint8_t flags,
    const uint8_t* data = nullptr, size_t len = 0);
bool tcp_send_packet6(Context* ctx, const TcpFlow* flow, uint8_t flags,
    const uint8_t* data = nullptr, size_t len = 0);
void tcp_destroy_flow(Context* ctx, TcpFlow* flow);
void push_to_guest(Context* ctx, TcpFlow* flow);

void handle_tcp4(Context* ctx, const ip4_hdr* ip, const uint8_t* data, size_t len);
void handle_tcp6(Context* ctx, const ip6_hdr* ip, const uint8_t* data, size_t len);
void handle_host_tcp(Context* ctx, TcpFlow* flow, uint32_t events);
void handle_host_tcp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);

} /* namespace nstun */

#endif /* NSTUN_TCP_H_ */