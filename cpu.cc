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

#include <memory>

#include "logs.h"
#include "util.h"

namespace cpu {

static size_t getNthCpu(cpu_set_t* mask, size_t mask_size, size_t n, size_t cpus_left) {
	for (size_t i = 0, j = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET_S(i, mask_size, mask)) {
			if (j == n) {
				return i;
			}
			j++;
		}
	}
	LOG_F("No CPU #%zu found, yet there should be %zu left", n,
	    (size_t)CPU_COUNT_S(mask_size, mask));
	return 0;
}

static void setRandomCpu(cpu_set_t* original_mask, cpu_set_t* new_mask, size_t mask_size) {
	size_t cpus_left = CPU_COUNT_S(mask_size, original_mask);
	if (cpus_left == 0) {
		LOG_F("There are no more CPUs left to use");
	}

	size_t n = getNthCpu(original_mask, mask_size, util::rnd64() % cpus_left, cpus_left);
	LOG_D("Setting allowed CPU#:%" PRIu64, n);
	CPU_SET_S(n, mask_size, new_mask);
	CPU_CLR_S(n, mask_size, original_mask);
}

bool initCpu(nsjconf_t* nsjconf) {
	if (nsjconf->max_cpus == 0) {
		LOG_D("No max_cpus limit set");
		return true;
	}

	size_t mask_size = CPU_ALLOC_SIZE(CPU_SETSIZE);
	std::unique_ptr<cpu_set_t> original_mask(CPU_ALLOC(CPU_SETSIZE));
	if (original_mask.get() == NULL) {
		PLOG_W("Failure allocating cpu_set_t for %d CPUs", CPU_SETSIZE);
		return false;
	}
	if (sched_getaffinity(0, mask_size, original_mask.get()) == -1) {
		PLOG_W("sched_getaffinity(0, mask_size=%zu)", mask_size);
		return false;
	}
	size_t available_cpus = CPU_COUNT_S(mask_size, original_mask.get());

	if (nsjconf->max_cpus > available_cpus) {
		LOG_W(
		    "Number of requested CPUs is bigger than number of available CPUs (%zu > %zu)",
		    nsjconf->max_cpus, available_cpus);
		return true;
	}
	if (nsjconf->max_cpus == available_cpus) {
		LOG_D("All CPUs requested (%zu of %zu)", nsjconf->max_cpus, available_cpus);
		return true;
	}

	std::unique_ptr<cpu_set_t> new_mask(CPU_ALLOC(CPU_SETSIZE));
	if (new_mask.get() == NULL) {
		PLOG_W("Failure allocating cpu_set_t for %d CPUs", CPU_SETSIZE);
		return false;
	}
	CPU_ZERO_S(mask_size, new_mask.get());

	for (size_t i = 0; i < nsjconf->max_cpus; i++) {
		setRandomCpu(original_mask.get(), new_mask.get(), mask_size);
	}

	if (sched_setaffinity(0, mask_size, new_mask.get()) == -1) {
		PLOG_W("sched_setaffinity(max_cpus=%zu) failed", nsjconf->max_cpus);
		return false;
	}

	return true;
}

}  // namespace cpu
