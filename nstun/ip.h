#ifndef NSTUN_IP_H_
#define NSTUN_IP_H_

#include <stddef.h>
#include <stdint.h>

#include <span>

#include "core.h"

namespace nstun {

void handle_ip4(Context* ctx, std::span<const uint8_t> payload);
void handle_ip6(Context* ctx, std::span<const uint8_t> payload);

}  // namespace nstun

#endif	// NSTUN_IP_H_
