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

#if !defined(TEMP_FAILURE_RETRY)
#define TEMP_FAILURE_RETRY(expression)                     \
	(__extension__({                                   \
		long int __result;                         \
		do __result = (long int)(expression);      \
		while (__result == -1L && errno == EINTR); \
		__result;                                  \
	}))
#endif /* !defined(TEMP_FAILURE_RETRY) */

#if !defined(ARR_SZ)
#define ARR_SZ(array) (sizeof(array) / sizeof(*array))
#endif /* !defined(ARR_SZ) */
#define UNUSED __attribute__((unused))

#if 0 /* Works, but needs -fblocks and libBlocksRuntime with clang */
/* Go-style defer implementation */
#define __STRMERGE(a, b) a##b
#define _STRMERGE(a, b) __STRMERGE(a, b)

#ifdef __clang__
static void __attribute__ ((unused)) __clang_cleanup_func(void (^*dfunc) (void))
{
	(*dfunc) ();
}

#define defer                                            \
	void (^_STRMERGE(__defer_f_, __COUNTER__))(void) \
	    __attribute__((cleanup(__clang_cleanup_func))) __attribute__((unused)) = ^
#else
#define __block
#define _DEFER(a, count)                                                                          \
	auto void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)));         \
	int _STRMERGE(__defer_var_, count) __attribute__((cleanup(_STRMERGE(__defer_f_, count)))) \
	__attribute__((unused));                                                                  \
	void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)))
#define defer _DEFER(a, __COUNTER__)
#endif
#endif

#define NS_VALSTR_STRUCT(x) \
	{ (uint64_t) x, #x }

#endif /* NS_COMMON_H */
