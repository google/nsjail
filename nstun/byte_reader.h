#ifndef NSTUN_BYTE_READER_H_
#define NSTUN_BYTE_READER_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <span>

namespace nstun {

/*
 * Bounds-checked cursor over a peer-controlled buffer.
 * Pointer and remaining length are one object; accessors never read past the end.
 */
class ByteReader {
    public:
	explicit ByteReader(std::span<const uint8_t> buf)
	    : buf_(buf) {
	}

	size_t remaining() const {
		return buf_.size();
	}

	const uint8_t* data() const {
		return buf_.data();
	}

	std::span<const uint8_t> span() const {
		return buf_;
	}

	bool skip(size_t n) {
		if (n > buf_.size()) {
			return false;
		}
		buf_ = buf_.subspan(n);
		return true;
	}

	bool peek_u8(size_t offset, uint8_t* out) const {
		if (offset >= buf_.size()) {
			return false;
		}
		*out = buf_[offset];
		return true;
	}

	template <typename T>
	bool peek(T* out) const {
		if (buf_.size() < sizeof(T)) {
			return false;
		}
		memcpy(out, buf_.data(), sizeof(T));
		return true;
	}

	template <typename T>
	bool read(T* out) {
		if (!peek(out)) {
			return false;
		}
		return skip(sizeof(T));
	}

    private:
	std::span<const uint8_t> buf_;
};

}  // namespace nstun

#endif	// NSTUN_BYTE_READER_H_
