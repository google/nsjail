#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include <array>

#include "nstun/ipparse.h"

namespace {

struct __attribute__((packed)) TestHeader {
	uint8_t a;
	uint16_t b;
};

void test_byte_reader() {
	std::array<uint8_t, 4> data = {0x01, 0x02, 0x03, 0x04};
	nstun::ByteReader reader(data);

	assert(reader.remaining() == 4);
	assert(!reader.empty());

	uint8_t value = 0;
	assert(reader.read_u8(&value));
	assert(value == 0x01);
	assert(reader.remaining() == 3);

	std::span<const uint8_t> bytes;
	assert(reader.read_bytes(2, &bytes));
	assert(bytes.size() == 2);
	assert(bytes[0] == 0x02);
	assert(bytes[1] == 0x03);
	assert(reader.remaining() == 1);

	assert(!reader.skip(2));
	assert(reader.remaining() == 1);
	assert(reader.skip(1));
	assert(reader.empty());
	assert(reader.rest().empty());
	assert(!reader.read_u8(&value));
	assert(!reader.skip(1));
}

void test_read_struct() {
	std::array<uint8_t, 4> data = {0x01, 0x02, 0x03, 0x04};
	nstun::ByteReader reader(data);

	TestHeader header;
	assert(reader.read_struct(&header));
	assert(memcmp(&header, data.data(), sizeof(header)) == 0);
	assert(reader.remaining() == 1);

	TestHeader untouched;
	memset(&untouched, 0xFF, sizeof(untouched));
	assert(!reader.read_struct(&untouched));
	assert(untouched.a == 0xFF);
	assert(untouched.b == 0xFFFF);
}

void test_no_extension_headers() {
	std::array<uint8_t, 4> data = {0x01, 0x02, 0x03, 0x04};
	nstun::ByteReader reader(data);

	assert(nstun::skip_ipv6_ext_headers(IPPROTO_TCP, &reader) == IPPROTO_TCP);
	assert(reader.remaining() == data.size());
}

void test_hop_by_hop() {
	std::array<uint8_t, 12> data = {};
	data[0] = IPPROTO_TCP;
	data[1] = 0; /* eight bytes */

	nstun::ByteReader reader(data);
	assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, &reader) == IPPROTO_TCP);
	assert(reader.remaining() == 4);
}

void test_authentication_header() {
	std::array<uint8_t, 12> data = {};
	data[0] = IPPROTO_UDP;
	data[1] = 0; /* eight bytes */

	nstun::ByteReader reader(data);
	assert(nstun::skip_ipv6_ext_headers(IPPROTO_AH, &reader) == IPPROTO_UDP);
	assert(reader.remaining() == 4);
}

void test_fragment_is_rejected() {
	std::array<uint8_t, 8> data = {};
	nstun::ByteReader reader(data);

	assert(nstun::skip_ipv6_ext_headers(IPPROTO_FRAGMENT, &reader) == -1);
	assert(reader.remaining() == data.size());
}

void test_truncated_extension_header() {
	std::array<uint8_t, 1> data = {};
	nstun::ByteReader reader(data);

	assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, &reader) == -1);
}

void test_extension_header_past_end() {
	std::array<uint8_t, 8> data = {};
	data[0] = IPPROTO_TCP;
	data[1] = 1; /* sixteen bytes, only eight available */

	nstun::ByteReader reader(data);
	assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, &reader) == -1);
}

void test_chain_depth() {
	/* Seven extension headers followed by TCP is accepted. */
	std::array<uint8_t, 7 * 8 + 4> seven = {};
	for (int i = 0; i < 7; ++i) {
		uint8_t next = static_cast<uint8_t>(IPPROTO_HOPOPTS);
		if (i == 6) {
			next = static_cast<uint8_t>(IPPROTO_TCP);
		}
		seven[static_cast<size_t>(i) * 8] = next;
		seven[static_cast<size_t>(i) * 8 + 1] = 0;
	}
	nstun::ByteReader seven_reader(seven);
	assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, &seven_reader) == IPPROTO_TCP);
	assert(seven_reader.remaining() == 4);

	/* An eighth extension header hits the depth limit. */
	std::array<uint8_t, 8 * 8 + 4> eight = {};
	for (int i = 0; i < 8; ++i) {
		uint8_t next = static_cast<uint8_t>(IPPROTO_HOPOPTS);
		if (i == 7) {
			next = static_cast<uint8_t>(IPPROTO_TCP);
		}
		eight[static_cast<size_t>(i) * 8] = next;
		eight[static_cast<size_t>(i) * 8 + 1] = 0;
	}
	nstun::ByteReader eight_reader(eight);
	assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, &eight_reader) == -1);
}

}  // namespace

int main() {
	test_byte_reader();
	test_read_struct();
	test_no_extension_headers();
	test_hop_by_hop();
	test_authentication_header();
	test_fragment_is_rejected();
	test_truncated_extension_header();
	test_extension_header_past_end();
	test_chain_depth();
	return 0;
}
