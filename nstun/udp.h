#ifndef NSTUN_UDP_H_
#define NSTUN_UDP_H_

#include <stddef.h>
#include <stdint.h>

#include "core.h"

namespace nstun {

void handle_udp(Context* ctx, const ip4_hdr* ip, const uint8_t* payload, size_t len);
void handle_host_udp(Context* ctx, int fd);
void handle_host_udp_control(Context* ctx, int fd, uint32_t events);
void udp_destroy_flow(Context* ctx, UdpFlow* flow);

}  // namespace nstun

#endif	// NSTUN_UDP_H_
