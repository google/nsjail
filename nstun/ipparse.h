#ifndef NSTUN_IPPARSE_H_
#define NSTUN_IPPARSE_H_

#include <stddef.h>
#include <stdint.h>

#include <cstring>
#include <span>
#include <type_traits>

namespace nstun {

/*
 * Bounds-checked cursor over a packet buffer.
 *
 * The span and the read offset are kept in the same object so a caller cannot
 * advance one without the other. Every accessor returns false instead of
 * reading past the end, and the output is left untouched on failure.
 */
class ByteReader {
public:
	explicit constexpr ByteReader(std::span<const uint8_t> data) : data_(data) {}

	[[nodiscard]] constexpr size_t remaining() const {
		return data_.size() - offset_;
	}
	[[nodiscard]] constexpr bool empty() const {
		return offset_ == data_.size();
	}
	[[nodiscard]] constexpr std::span<const uint8_t> rest() const {
		return data_.subspan(offset_);
	}

	[[nodiscard]] bool skip(size_t count) {
		if (count > remaining()) {
			return false;
		}
		offset_ += count;
		return true;
	}

	[[nodiscard]] bool read_u8(uint8_t* out) {
		if (remaining() < sizeof(*out)) {
			return false;
		}
		*out = data_[offset_++];
		return true;
	}

	[[nodiscard]] bool read_bytes(size_t count, std::span<const uint8_t>* out) {
		if (count > remaining()) {
			return false;
		}
		*out = data_.subspan(offset_, count);
		offset_ += count;
		return true;
	}

	template <typename T>
	[[nodiscard]] bool read_struct(T* out) {
		static_assert(std::is_trivially_copyable_v<T>);
		if (remaining() < sizeof(T)) {
			return false;
		}
		std::memcpy(out, data_.data() + offset_, sizeof(T));
		offset_ += sizeof(T);
		return true;
	}

private:
	std::span<const uint8_t> data_;
	size_t offset_ = 0;
};

/* Maximum number of IPv6 extension headers nstun walks. */
constexpr int kMaxIpv6ExtensionHeaders = 8;

/*
 * Walk an IPv6 extension-header chain.
 *
 * `reader` must point at the first extension header, or at the L4 header when
 * `next_header` is not an extension header. On success the function returns
 * the L4 protocol number and leaves `reader` at the L4 header. It returns -1
 * for fragments, malformed lengths, or a chain deeper than
 * kMaxIpv6ExtensionHeaders.
 */
[[nodiscard]] int skip_ipv6_ext_headers(int next_header, ByteReader* reader);

}  // namespace nstun

#endif /* NSTUN_IPPARSE_H_ */
