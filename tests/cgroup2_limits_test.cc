/*
 * Regression tests for the cgroup v2 memory/swap limit derivation.
 *
 * cgroup_mem_memsw_max is a combined RAM+swap ceiling, but cgroup v2 has no single
 * control file for it, so cgroup2::effectiveMemLimits() maps it onto memory.max and
 * memory.swap.max. These tests pin that mapping for representative and boundary
 * combinations.
 *
 * A zero mem_max means memory.max is left alone; a negative swap_max means
 * memory.swap.max is left alone.
 */

#include <assert.h>
#include <stddef.h>
#include <sys/types.h>

#include "cgroup2.h"
#include "config.pb.h"
#include "nsjail.h"

static const size_t kMem32M = 33554432;
static const size_t kMem64M = 67108864;
static const size_t kMem128M = 134217728;

/* A negative value in either expectation means "left alone". */
static void expect(size_t mem_max, size_t memsw_max, ssize_t swap_max, size_t want_mem_max,
    ssize_t want_swap_max) {
	nsj_t nsj;
	nsj.njc.set_cgroup_mem_max(mem_max);
	nsj.njc.set_cgroup_mem_memsw_max(memsw_max);
	nsj.njc.set_cgroup_mem_swap_max(swap_max);

	size_t got_mem_max = 0;
	ssize_t got_swap_max = 0;
	cgroup2::effectiveMemLimits(&nsj, &got_mem_max, &got_swap_max);

	assert(got_mem_max == want_mem_max);
	if (want_swap_max < (ssize_t)0) {
		assert(got_swap_max < (ssize_t)0);
	} else {
		assert(got_swap_max == want_swap_max);
	}
}

int main() {
	/* No limits at all, and an explicit swap limit on its own. */
	expect(0, 0, -1, 0, -1);
	expect(0, 0, 0, 0, 0);
	expect(0, 0, kMem32M, 0, kMem32M);

	/*
	 * A combined ceiling with no separate RAM limit has to bound RAM as well,
	 * otherwise only the swap half of the requested ceiling would be applied.
	 */
	expect(0, kMem32M, -1, kMem32M, 0);
	expect(0, kMem64M, -1, kMem64M, 0);
	expect(0, kMem128M, -1, kMem128M, 0);

	/* A RAM limit on its own, with and without an explicit swap limit. */
	expect(kMem64M, 0, -1, kMem64M, -1);
	expect(kMem64M, 0, 0, kMem64M, 0);
	expect(kMem64M, 0, kMem32M, kMem64M, kMem32M);

	/* A combined ceiling alongside a RAM limit leaves the remainder for swap. */
	expect(kMem64M, kMem64M, -1, kMem64M, 0);
	expect(kMem64M, kMem128M, -1, kMem64M, kMem64M);

	/* A combined ceiling below the RAM limit leaves nothing for swap. */
	expect(kMem64M, kMem32M, -1, kMem64M, -1);

	return 0;
}
