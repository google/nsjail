/*

   nsjail - common macros
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

#ifndef NS_COMMON_H
#define NS_COMMON_H

#include <unistd.h>

#include <utility>

#if !defined(TEMP_FAILURE_RETRY)
#define TEMP_FAILURE_RETRY(expression)                                                             \
	(__extension__({                                                                           \
		long int __result;                                                                 \
		do __result = (long int)(expression);                                              \
		while (__result == -1L && errno == EINTR);                                         \
		__result;                                                                          \
	}))
#endif /* !defined(TEMP_FAILURE_RETRY) */

#if !defined(ARR_SZ)
#define ARR_SZ(array) (sizeof(array) / sizeof(*array))
#endif /* !defined(ARR_SZ) */

#define NS_VALSTR_STRUCT(x) {(uint64_t)x, #x}

/* go-style defer */
template <typename F>
struct Defer {
	F f;
	Defer(F f) : f(std::move(f)) {
	}
	~Defer() noexcept {
		f();
	}

	Defer(const Defer&) = delete;
	Defer& operator=(const Defer&) = delete;
	Defer(Defer&&) = default;
	Defer& operator=(Defer&&) = default;
};

#define _DEFER_1(x, y) x##y
#define _DEFER_2(x, y) _DEFER_1(x, y)
#define _DEFER_3(x) _DEFER_2(x, __COUNTER__)
#define defer [[maybe_unused]] Defer _DEFER_3(_defer_) = [&]()

#endif /* NS_COMMON_H */
