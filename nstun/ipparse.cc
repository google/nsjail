#include "ipparse.h"

#include <netinet/in.h>

namespace nstun {

int skip_ipv6_ext_headers(int next_header, ByteReader& r) {
	constexpr int MAX_EXT = 8; /* Defense: cap chain depth */
	for (int i = 0; i < MAX_EXT; ++i) {
		size_t ext_len = 0;
		bool is_ext = true;
		switch (next_header) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case 139: /* Host Identity Protocol */
		case 140: { /* Shim6 */
			uint8_t len_field = 0;
			if (!r.peek_u8(1, &len_field)) {
				return -1;
			}
			ext_len = ((size_t)len_field + 1) * 8;
			break;
		}
		case IPPROTO_FRAGMENT:
			/* nstun does not reassemble fragments. Drop unconditionally
			 * to match IPv4 behavior and prevent L4 port-based rule
			 * bypass via non-first fragments. */
			return -1;
		case IPPROTO_AH: { /* Authentication Header */
			uint8_t len_field = 0;
			if (!r.peek_u8(1, &len_field)) {
				return -1;
			}
			ext_len = ((size_t)len_field + 2) * 4;
			break;
		}
		default:
			is_ext = false;
			break;
		}

		if (!is_ext) {
			return next_header;
		}
		if (ext_len == 0 || ext_len > r.remaining()) {
			return -1;
		}

		uint8_t following = 0;
		if (!r.peek_u8(0, &following)) {
			return -1;
		}
		if (!r.skip(ext_len)) {
			return -1;
		}
		next_header = following;
	}
	return -1; /* Extension header chain too deep */
}

}  // namespace nstun
