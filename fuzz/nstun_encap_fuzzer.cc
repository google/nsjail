#include <stddef.h>
#include <stdint.h>

#include <span>
#include <vector>

#include "nstun/encap.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	std::span<const uint8_t> sp(data, size);
	nstun::parse_socks5_auth_reply(sp);

	nstun::Socks5Reply reply = {};
	nstun::parse_socks5_connect_reply(sp, &reply);

	std::vector<uint8_t> vec(data, data + size);
	nstun::find_end_of_headers(vec);
	nstun::parse_http_connect_reply(vec);
	return 0;
}
