#include <assert.h>

#include <arpa/inet.h>
#include <stdint.h>

#include <array>

#include "nstun/net_defs.h"

static uint32_t parse_ip4(const char* str) {
	uint32_t addr;
	assert(inet_pton(AF_INET, str, &addr) == 1);
	return addr;
}

static bool ip6_is_aws_local_service(const char* str) {
	std::array<uint8_t, 16> addr = {};
	assert(inet_pton(AF_INET6, str, addr.data()) == 1);
	return nstun::ip6_is_aws_local_service(addr.data());
}

int main() {
	assert(!nstun::ip4_is_link_local(parse_ip4("169.253.255.255")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.0.0")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.169.254")));
	assert(nstun::ip4_is_link_local(parse_ip4("169.254.255.255")));
	assert(!nstun::ip4_is_link_local(parse_ip4("169.255.0.0")));
	assert(!nstun::ip4_is_link_local(parse_ip4("127.0.0.1")));
	assert(!nstun::ip4_is_link_local(parse_ip4("10.0.0.1")));

	assert(!ip6_is_aws_local_service("fd00:ec1:ffff:ffff:ffff:ffff:ffff:ffff"));
	assert(ip6_is_aws_local_service("fd00:ec2::"));
	assert(ip6_is_aws_local_service("fd00:ec2::254"));
	assert(ip6_is_aws_local_service("fd00:ec2:ffff:ffff:ffff:ffff:ffff:ffff"));
	assert(!ip6_is_aws_local_service("fd00:ec3::"));
	assert(!ip6_is_aws_local_service("fc00::1"));
	assert(!ip6_is_aws_local_service("fe80::1"));
	return 0;
}
