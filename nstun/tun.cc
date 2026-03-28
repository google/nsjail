#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "core.h"
#include "logs.h"

namespace nstun {

bool send_to_guest(Context* ctx, const void* data, size_t len) {
	ssize_t written = TEMP_FAILURE_RETRY(write(ctx->tap_fd, data, len));
	if (written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Saturated queue, drop packet normally */
			return false;
		}
		PLOG_E("write(tap_fd) failed");
		return false;
	}
	if ((size_t)written != len) {
		LOG_E("write(tap_fd) partial write: %zd of %zu", written, len);
		return false;
	}

	return true;
}

void handle_tun_frame(Context* ctx, const uint8_t* buf, size_t len) {
	if (len < 1) {
		return;
	}

	uint8_t version = buf[0] >> 4;

	switch (version) {
	case 4:
		handle_ip4(ctx, buf, len);
		break;
	case 6:
		/* TODO: IPv6 */
		break;
	default:
		LOG_D("Unknown IP version: %u", version);
		break;
	}
}

}  // namespace nstun