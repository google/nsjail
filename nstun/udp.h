#ifndef NSTUN_UDP_H_
#define NSTUN_UDP_H_

#include <stddef.h>
#include <stdint.h>

#include "core.h"

namespace nstun {

void handle_udp4(Context* ctx, const ip4_hdr* ip, const uint8_t* data, size_t len);
void handle_udp6(Context* ctx, const ip6_hdr* ip, const uint8_t* data, size_t len);
void handle_host_udp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);
void handle_host_udp_event(Context* ctx, UdpFlow* flow, int fd, uint32_t events);
bool is_stale_udp(const UdpFlow* flow, time_t now);
void udp_destroy_flow(Context* ctx, UdpFlow* flow);

}  // namespace nstun

#endif	// NSTUN_UDP_H_
