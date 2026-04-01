#ifndef NSTUN_UDP_H_
#define NSTUN_UDP_H_

#include <stddef.h>
#include <stdint.h>

#include <span>

#include "core.h"

namespace nstun {

void handle_udp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload);
void handle_udp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload);
void handle_host_udp_accept(Context* ctx, int listen_fd, const nstun_rule_t& rule);

}  // namespace nstun

#endif	// NSTUN_UDP_H_
