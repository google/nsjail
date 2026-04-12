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

bool send_to_guest_v(Context* ctx, const virtio_net_hdr* vh, const void* header, size_t header_len,
    const void* payload, size_t payload_len) {
	if (header_len > NSTUN_MTU || payload_len > NSTUN_MTU - header_len) {
		LOG_W("send_to_guest_v: frame too large (%zu + %zu)", header_len, payload_len);
		return false;
	}

	struct iovec iov[3];
	int iovcnt = 0;

	iov[iovcnt].iov_base = const_cast<virtio_net_hdr*>(vh);
	iov[iovcnt].iov_len = VNET_HDR_SIZE;
	iovcnt++;

	iov[iovcnt].iov_base = const_cast<void*>(header);
	iov[iovcnt].iov_len = header_len;
	iovcnt++;

	if (payload_len > 0) {
		iov[iovcnt].iov_base = const_cast<void*>(payload);
		iov[iovcnt].iov_len = payload_len;
		iovcnt++;
	}

	size_t total_len = VNET_HDR_SIZE + header_len + payload_len;
	ssize_t written = TEMP_FAILURE_RETRY(writev(ctx->tap_fd, iov, iovcnt));
	if (written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return false;
		}
		PLOG_E("writev(tap_fd) failed");
		return false;
	}
	if ((size_t)written != total_len) {
		LOG_E("writev(tap_fd) partial write: %zd of %zu", written, total_len);
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
		handle_ip6(ctx, buf, len);
		break;
	default:
		LOG_D("Unknown IP version: %u", version);
		break;
	}
}

}  // namespace nstun