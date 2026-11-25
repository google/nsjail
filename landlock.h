/*

   nsjail - optional Landlock filesystem layer
   -----------------------------------------

   Copyright 2026 Google Inc. All Rights Reserved.

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

#ifndef NS_LANDLOCK_H
#define NS_LANDLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include "nsjail.h"

namespace landlock {

/* Returns the Landlock filesystem access bitmask supported by the given ABI version. */
uint64_t handledAccessForAbi(int abi);

/* Computes the Landlock allowed_access mask for a single mount point. */
uint64_t accessForMount(const nsjail::MountPt& mpt, bool is_dir, uint64_t handled);

/*
 * Restrict the calling process with a Landlock ruleset derived from the mount list. Must be called
 * after the mount namespace is set up (paths are resolved inside the jail) and before the seccomp
 * policy is applied. A no-op when the 'landlock' option is LANDLOCK_OFF.
 */
bool apply(nsj_t* nsj);

}  // namespace landlock

#endif /* NS_LANDLOCK_H */
