#include "nstun/core.h"
#include "nstun/tcp.h"
#include "nstun/udp.h"
#include "nstun/icmp.h"
#include "nstun/tun.h"

namespace nstun {
void fuzz_feed(Context* ctx, const uint8_t* data, size_t size) {
        handle_tun_frame(ctx, data, size);
}
Context* fuzz_ctx_new() {
        Context* c = new Context();
        c->tap_fd = -1;
        c->epoll_fd = -1;
        c->stop_fd = -1;
        c->nsj = nullptr;
        c->guest_ip4 = 0x0A000002U;
        c->host_ip4 = 0x0A000001U;
        c->guest_ip6[15] = 0x02;
        c->host_ip6[15] = 0x01;
        return c;
}
} /* namespace nstun */
