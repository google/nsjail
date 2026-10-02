/*
 * bounds_safety.h — portability macros for optional -fbounds-safety
 *
 * Copyright 2026 Jeff Bindel <jeff@incrediblybased.co>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * When NSJAIL_SUPPORT_FBOUNDS_SAFETY is defined (typically via
 * -DNSJAIL_SUPPORT_FBOUNDS_SAFETY and a Clang toolchain that implements
 * -fbounds-safety), these macros expand to Clang bounds annotations.
 * Otherwise they expand to nothing so default builds are unchanged.
 *
 * Pattern matches libwebp / libpng / lz4 inert-macro -fbounds-safety
 * adoption: annotations are inert unless explicitly enabled.
 */
#ifndef NSJAIL_BOUNDS_SAFETY_H_
#define NSJAIL_BOUNDS_SAFETY_H_

#ifdef NSJAIL_SUPPORT_FBOUNDS_SAFETY

#include <ptrcheck.h>
/* Non-ABI-breaking sized-by annotations for buffer pointer parameters.
 * Prefer NSJAIL_SIZED_BY when the companion argument is a byte capacity.
 * Use *_OR_NULL when the pointer may be NULL while the size is zero.
 */
#define NSJAIL_SIZED_BY(n) __sized_by(n)
#define NSJAIL_SIZED_BY_OR_NULL(n) __sized_by_or_null(n)
#define NSJAIL_COUNTED_BY(n) __counted_by(n)
#define NSJAIL_COUNTED_BY_OR_NULL(n) __counted_by_or_null(n)

#else /* !NSJAIL_SUPPORT_FBOUNDS_SAFETY */

#define NSJAIL_SIZED_BY(n)
#define NSJAIL_SIZED_BY_OR_NULL(n)
#define NSJAIL_COUNTED_BY(n)
#define NSJAIL_COUNTED_BY_OR_NULL(n)

#endif /* NSJAIL_SUPPORT_FBOUNDS_SAFETY */

#endif /* NSJAIL_BOUNDS_SAFETY_H_ */
