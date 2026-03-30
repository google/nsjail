#include "tun.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core.h"
#include "icmp.h"
#include "ip.h"
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

bool send_to_guest_v(
    Context* ctx, const void* header, size_t header_len, const void* payload, size_t payload_len) {
	struct iovec iov[2];
	iov[0].iov_base = (void*)header;
	iov[0].iov_len = header_len;
	iov[1].iov_base = (void*)payload;
	iov[1].iov_len = payload_len;

	ssize_t total_len = header_len + payload_len;
	ssize_t written = TEMP_FAILURE_RETRY(writev(ctx->tap_fd, iov, payload_len > 0 ? 2 : 1));
	if (written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return false;
		}
		PLOG_E("writev(tap_fd) failed");
		return false;
	}
	if ((size_t)written != (size_t)total_len) {
		LOG_E("writev(tap_fd) partial write: %zd of %zd", written, total_len);
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