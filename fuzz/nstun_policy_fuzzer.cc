#include <stddef.h>
#include <stdint.h>

#include <array>
#include <string>

#include "logs.h"
#include "nstun/policy.h"

namespace logs {
void logMsg(enum llevel_t, const char*, int, bool, const char*, ...) {}
enum llevel_t getLogLevel() { return ERROR; }
}  // namespace logs

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	std::string input(reinterpret_cast<const char*>(data), size);
	uint32_t ip4 = 0;
	uint32_t mask4 = 0;
	nstun::parse_ip4_cidr(input, &ip4, &mask4);

	std::array<uint8_t, 16> ip6 = {};
	std::array<uint8_t, 16> mask6 = {};
	nstun::parse_ip6_cidr(input, ip6.data(), mask6.data());
	return 0;
}
