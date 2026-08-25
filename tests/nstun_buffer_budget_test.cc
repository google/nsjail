#include <limits>

#include "nstun/buffer_budget.h"

int main() {
	nstun::BufferBudget budget(64);
	if (budget.limit() != 64 || budget.used() != 0) return 1;
	if (!budget.try_reserve(32) || budget.used() != 32) return 2;
	if (budget.try_reserve(33) || budget.used() != 32) return 3;
	if (!budget.release(16) || budget.used() != 16) return 4;
	if (!budget.try_reserve(48) || budget.used() != 64) return 5;
	if (budget.try_reserve(1) || budget.used() != 64) return 6;
	if (!budget.release(64) || budget.used() != 0) return 7;
	if (budget.release(1) || budget.used() != 0) return 8;
	if (budget.try_reserve(std::numeric_limits<size_t>::max()) || budget.used() != 0) return 9;
	return 0;
}
