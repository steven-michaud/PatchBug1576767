/* The MIT License (MIT)
 *
 * Copyright (c) 2020 Steven Michaud
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* This file must be includable in PatchBug1576767.s.  So basically everything
 * but #defines should be isolated in "#ifndef __ASSEMBLER__" blocks.  And
 * don't use // comments.
 */

#ifndef PatchBug1576767_h
#define PatchBug1576767_h

#ifndef __ASSEMBLER__

extern "C" Boolean OSCompareAndSwap_fixed(UInt32 oldValue, UInt32 newValue,
                                          volatile UInt32 *address);
extern "C" Boolean OSCompareAndSwap64_fixed(UInt64 oldValue, UInt64 newValue,
                                            volatile UInt64 *address);
extern "C" Boolean OSCompareAndSwapPtr_fixed(void *oldValue, void *newValue,
                                             void * volatile *address);

#undef OSCompareAndSwap
#define OSCompareAndSwap OSCompareAndSwap_fixed
#undef OSCompareAndSwap64
#define OSCompareAndSwap64 OSCompareAndSwap64_fixed
#undef OSCompareAndSwapPtr
#define OSCompareAndSwapPtr OSCompareAndSwapPtr_fixed

extern "C" Boolean OSCompareAndSwap128(__uint128_t oldValue, __uint128_t newValue,
                                       volatile __uint128_t *address);

#endif /* #ifndef __ASSEMBLER__ */

#endif /* PatchBug1576767_h */
