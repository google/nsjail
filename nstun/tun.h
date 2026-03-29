#ifndef NSTUN_TUN_H_
#define NSTUN_TUN_H_

#include <stddef.h>
#include <stdint.h>

#include "core.h"

namespace nstun {

bool send_to_guest(Context* ctx, const void* data, size_t len);
void handle_tun_frame(Context* ctx, const uint8_t* buf, size_t len);

}  // namespace nstun

#endif /* NSTUN_TUN_H_ */
