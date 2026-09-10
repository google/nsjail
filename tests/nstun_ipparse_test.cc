#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "nstun/byte_reader.h"
#include "nstun/ipparse.h"

static std::vector<uint8_t> hopopts(uint8_t next, uint8_t len_field) {
	size_t len = ((size_t)len_field + 1) * 8;
	std::vector<uint8_t> h(len, 0);
	h[0] = next;
	h[1] = len_field;
	return h;
}

int main() {
	{
		std::span<const uint8_t> none;
		nstun::ByteReader empty(none);
		assert(empty.remaining() == 0);
		assert(!empty.skip(1));
		uint8_t b = 0xff;
		assert(!empty.peek_u8(0, &b));
	}

	{
		const uint8_t bytes[] = {0x11, 0x22, 0x33, 0x44};
		nstun::ByteReader r(std::span<const uint8_t>(bytes, sizeof(bytes)));
		uint16_t w = 0;
		assert(r.peek(&w));
		assert(!r.skip(5));
		assert(r.skip(2));
		assert(r.remaining() == 2);
		assert(r.data()[0] == 0x33);
	}

	{
		/* Direct TCP: no extension headers */
		std::vector<uint8_t> buf(20, 0);
		nstun::ByteReader r(buf);
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_TCP, r) == IPPROTO_TCP);
		assert(r.remaining() == 20);
	}

	{
		/* Truncated hop-by-hop (need 2 bytes for Next Header + Hdr Ext Len) */
		uint8_t one = 0x06;
		nstun::ByteReader r(std::span<const uint8_t>(&one, 1));
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, r) == -1);
	}

	{
		/* Hop-by-hop claiming length larger than remaining */
		std::vector<uint8_t> h = hopopts(IPPROTO_TCP, 1); /* 16 bytes claimed */
		h.resize(8);
		nstun::ByteReader r(h);
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, r) == -1);
	}

	{
		/* Valid hop-by-hop then TCP */
		std::vector<uint8_t> h = hopopts(IPPROTO_TCP, 0);
		h.insert(h.end(), 8, 0xaa);
		nstun::ByteReader r(h);
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, r) == IPPROTO_TCP);
		assert(r.remaining() == 8);
		assert(r.data()[0] == 0xaa);
	}

	{
		/* Fragment header is always dropped */
		uint8_t frag[8] = {IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0};
		nstun::ByteReader r(std::span<const uint8_t>(frag, sizeof(frag)));
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_FRAGMENT, r) == -1);
	}

	{
		/* Chain deeper than MAX_EXT=8 */
		std::vector<uint8_t> chain;
		for (int i = 0; i < 9; ++i) {
			auto h = hopopts(IPPROTO_HOPOPTS, 0);
			chain.insert(chain.end(), h.begin(), h.end());
		}
		nstun::ByteReader r(chain);
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_HOPOPTS, r) == -1);
	}

	{
		/* AH length encoding: (len_field + 2) * 4 */
		/* len_field=0 => 8 bytes */
		uint8_t ah[8] = {IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0};
		nstun::ByteReader r(std::span<const uint8_t>(ah, sizeof(ah)));
		assert(nstun::skip_ipv6_ext_headers(IPPROTO_AH, r) == IPPROTO_UDP);
		assert(r.remaining() == 0);
	}

	return 0;
}
