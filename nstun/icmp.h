#ifndef NSTUN_ICMP_H_
#define NSTUN_ICMP_H_

#include <stddef.h>
#include <stdint.h>

#include <span>

#include "core.h"

namespace nstun {

void handle_icmp4(Context* ctx, const ip4_hdr* ip, std::span<const uint8_t> payload);
void handle_icmp6(Context* ctx, const ip6_hdr* ip, std::span<const uint8_t> payload);

void send_icmp4_error(
    Context* ctx, const ip4_hdr* req_ip, size_t tot_len, uint8_t type, uint8_t code);
void send_icmp6_error(
    Context* ctx, const ip6_hdr* req_ip, size_t tot_len, uint8_t type, uint8_t code);

}  // namespace nstun

#endif	// NSTUN_ICMP_H_
