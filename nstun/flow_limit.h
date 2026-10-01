#ifndef NSTUN_FLOW_LIMIT_H_
#define NSTUN_FLOW_LIMIT_H_

#include <stddef.h>

namespace nstun {

[[nodiscard]] inline bool flow_limit_reached(size_t ipv4_count, size_t ipv6_count, size_t limit) {
	if (ipv4_count >= limit) {
		return true;
	}
	return ipv6_count >= limit - ipv4_count;
}

} /* namespace nstun */

#endif /* NSTUN_FLOW_LIMIT_H_ */
