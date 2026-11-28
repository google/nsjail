#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#include <span>

#include "logs.h"
#include "nstun/core.h"
#include "nstun/icmp.h"
#include "nstun/ip.h"
#include "nstun/net_defs.h"
#include "nstun/tcp.h"
#include "nstun/udp.h"

namespace logs {
void logMsg(enum llevel_t, const char*, int, bool, const char*, ...) {}
enum llevel_t getLogLevel() { return ERROR; }
}  // namespace logs

namespace nstun {
Context::~Context() = default;
void handle_udp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {}
void handle_udp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}
void handle_tcp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {}
void handle_tcp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}
void handle_icmp4(Context*, const ip4_hdr*, std::span<const uint8_t>) {}
void handle_icmp6(Context*, const ip6_hdr*, std::span<const uint8_t>) {}
}  // namespace nstun

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 2) return 0;

	nstun::Context ctx = {};
	inet_pton(AF_INET, "10.0.0.2", &ctx.guest_ip4);
	inet_pton(AF_INET6, "fd00::2", ctx.guest_ip6);

	std::span<const uint8_t> pkt(data + 1, size - 1);
	if (data[0] & 1) {
		nstun::handle_ip4(&ctx, pkt);
	} else {
		nstun::handle_ip6(&ctx, pkt);
	}
	return 0;
}
