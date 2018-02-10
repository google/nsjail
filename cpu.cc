/*

   nsjail - CPU affinity
   -----------------------------------------

   Copyright 2017 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "cpu.h"

#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "logs.h"
#include "util.h"

namespace cpu {

static void setRandomCpu(cpu_set_t* mask, size_t mask_size, size_t cpu_num) {
	if ((size_t)CPU_COUNT_S(mask_size, mask) >= cpu_num) {
		LOG_F(
		    "Number of CPUs in the mask '%d' is bigger than number of available CPUs '%zu'",
		    CPU_COUNT(mask), cpu_num);
	}

	for (;;) {
		uint64_t n = util::rnd64() % cpu_num;
		if (!CPU_ISSET_S(n, mask_size, mask)) {
			LOG_D("Setting allowed CPU#:%" PRIu64 " of [0-%zu]", n, cpu_num - 1);
			CPU_SET_S(n, mask_size, mask);
			break;
		}
	}
}

bool initCpu(nsjconf_t* nsjconf) {
	if (nsjconf->num_cpus < 0) {
		PLOG_W("sysconf(_SC_NPROCESSORS_ONLN) returned %ld", nsjconf->num_cpus);
		return false;
	}
	if (nsjconf->max_cpus > (size_t)nsjconf->num_cpus) {
		LOG_W("Requested number of CPUs:%zu is bigger than CPUs online:%ld",
		    nsjconf->max_cpus, nsjconf->num_cpus);
		return true;
	}
	if (nsjconf->max_cpus == (size_t)nsjconf->num_cpus) {
		LOG_D("All CPUs requested (%zu of %ld)", nsjconf->max_cpus, nsjconf->num_cpus);
		return true;
	}
	if (nsjconf->max_cpus == 0) {
		LOG_D("No max_cpus limit set");
		return true;
	}

	cpu_set_t* mask = CPU_ALLOC(nsjconf->num_cpus);
	if (mask == NULL) {
		PLOG_W("Failure allocating cpu_set_t for %ld CPUs", nsjconf->num_cpus);
		return false;
	}

	size_t mask_size = CPU_ALLOC_SIZE(nsjconf->num_cpus);
	CPU_ZERO_S(mask_size, mask);

	for (size_t i = 0; i < nsjconf->max_cpus; i++) {
		setRandomCpu(mask, mask_size, nsjconf->num_cpus);
	}

	if (sched_setaffinity(0, mask_size, mask) == -1) {
		PLOG_W("sched_setaffinity(max_cpus=%zu) failed", nsjconf->max_cpus);
		CPU_FREE(mask);
		return false;
	}
	CPU_FREE(mask);

	return true;
}

}  // namespace cpu
