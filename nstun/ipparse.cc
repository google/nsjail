#include "ipparse.h"

#include <netinet/in.h>

namespace nstun {
namespace {

/*
 * Extension headers with a length byte. The fragment header is not included
 * here: nstun does not reassemble fragments, so it is dropped before reading
 * any of its fields.
 */
bool is_ipv6_extension_header(int next_header) {
	switch (next_header) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_AH:
	case 139: /* Host Identity Protocol */
	case 140: /* Shim6 */
		return true;
	default:
		return false;
	}
}

}  // namespace

int skip_ipv6_ext_headers(int next_header, ByteReader* reader) {
	if (reader == nullptr) {
		return -1;
	}

	for (int i = 0; i < kMaxIpv6ExtensionHeaders; ++i) {
		if (next_header == IPPROTO_FRAGMENT) {
			return -1;
		}
		if (!is_ipv6_extension_header(next_header)) {
			return next_header;
		}

		uint8_t next;
		uint8_t length;
		if (!reader->read_u8(&next) || !reader->read_u8(&length)) {
			return -1;
		}

		size_t ext_len;
		if (next_header == IPPROTO_AH) {
			ext_len = (static_cast<size_t>(length) + 2) * 4;
		} else {
			ext_len = (static_cast<size_t>(length) + 1) * 8;
		}

		/* The two bytes above are already consumed. */
		if (ext_len < 2 || !reader->skip(ext_len - 2)) {
			return -1;
		}
		next_header = next;
	}

	return -1;
}

}  // namespace nstun
