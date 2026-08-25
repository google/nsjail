#ifndef NSTUN_BUFFER_BUDGET_H_
#define NSTUN_BUFFER_BUDGET_H_

#include <stddef.h>

namespace nstun {

class BufferBudget {
public:
	explicit constexpr BufferBudget(size_t limit) : limit_(limit) {}

	[[nodiscard]] bool try_reserve(size_t bytes) {
		if (bytes > limit_ - used_) {
			return false;
		}
		used_ += bytes;
		return true;
	}

	[[nodiscard]] bool release(size_t bytes) {
		if (bytes > used_) {
			return false;
		}
		used_ -= bytes;
		return true;
	}

	[[nodiscard]] size_t used() const { return used_; }
	[[nodiscard]] size_t limit() const { return limit_; }

private:
	size_t limit_;
	size_t used_ = 0;
};

} /* namespace nstun */

#endif /* NSTUN_BUFFER_BUDGET_H_ */
