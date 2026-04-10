#ifndef NSTUN_IP_H_
#define NSTUN_IP_H_

#include <stddef.h>
#include <stdint.h>

#include "core.h"

namespace nstun {

void handle_ip4(Context* ctx, const uint8_t* payload, size_t len);
void handle_ip6(Context* ctx, const uint8_t* payload, size_t len);

}  // namespace nstun

#endif	// NSTUN_IP_H_
