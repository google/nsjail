#include <limits>

#include "nstun/flow_limit.h"

int main() {
	constexpr size_t limit = 1024;
	if (nstun::flow_limit_reached(0, 0, limit)) return 1;
	if (nstun::flow_limit_reached(1023, 0, limit)) return 2;
	if (nstun::flow_limit_reached(0, 1023, limit)) return 3;
	if (nstun::flow_limit_reached(512, 511, limit)) return 4;
	if (!nstun::flow_limit_reached(512, 512, limit)) return 5;
	if (!nstun::flow_limit_reached(1024, 0, limit)) return 6;
	if (!nstun::flow_limit_reached(0, 1024, limit)) return 7;
	if (!nstun::flow_limit_reached(
		std::numeric_limits<size_t>::max(), std::numeric_limits<size_t>::max(), limit)) {
		return 8;
	}
	return 0;
}
