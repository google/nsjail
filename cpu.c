/*

   nsjail - CLONE_NEWUTS routines
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

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

#include <sched.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

static void cpuSetRandomCpu(cpu_set_t * mask, size_t mask_size, size_t cpu_num)
{
	if ((size_t) CPU_COUNT_S(mask_size, mask) >= cpu_num) {
		LOG_F
		    ("Number of CPUs in the mask '%d' is bigger than number of available CPUs '%zu'",
		     CPU_COUNT(mask), cpu_num);
	}

	for (;;) {
		uint64_t n = utilRnd64() % cpu_num;
		if (!CPU_ISSET_S(n, mask_size, mask)) {
			CPU_SET_S(n, mask_size, mask);
			break;
		}
	}
}

bool cpuInit(struct nsjconf_t *nsjconf)
{
	long all_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (all_cpus < 0) {
		PLOG_W("sysconf(_SC_NPROCESSORS_ONLN) returned %ld", all_cpus);
		return false;
	}
	if (nsjconf->max_cpu_num >= (size_t) all_cpus) {
		LOG_D("Requested number of CPUs '%zu' is bigger that CPUs online '%ld'",
		      nsjconf->max_cpu_num, all_cpus);
		return true;
	}
	if (nsjconf->max_cpu_num == 0) {
		LOG_D("No max_cpu_num limit set");
		return true;
	}

	cpu_set_t *mask = CPU_ALLOC(all_cpus);
	if (mask == NULL) {
		PLOG_W("Failure allocating cpu_set_t for %ld CPUs", all_cpus);
		return false;
	}

	size_t mask_size = CPU_ALLOC_SIZE(all_cpus);
	CPU_ZERO_S(mask_size, mask);

	for (size_t i = 0; i < nsjconf->max_cpu_num; i++) {
		cpuSetRandomCpu(mask, mask_size, all_cpus);
	}

	if (sched_setaffinity(0, mask_size, mask) == -1) {
		PLOG_W("sched_setaffinity(max_cpu_num=%zu) failed", nsjconf->max_cpu_num);
		return false;
	}

	return true;
}
