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

#define ALIGN 4,0x90
#include <i386/asm.h>
#include "PatchBug1576767.h"

/* In developer and debug kernels, the OSCompareAndSwap...() all enforce a
 * requirement that 'address' be 4-byte aligned.  But this is actually only
 * needed by Intel hardware in user mode, and it's much more convenient for
 * us to be able to ignore it.  So we need "fixed" versions of these methods
 * that don't (ever) enforce this requirement.
 */

/* Boolean OSCompareAndSwap(UInt32 oldValue, UInt32 newValue,
 *                          volatile UInt32 *address);
 *
 * Called with:
 *
 *   EDI == oldValue
 *   ESI == newValue
 *   RDX == address
 */
Entry(OSCompareAndSwap_fixed)
   push    %rbp
   mov     %rsp, %rbp

   cmp     $0, %rdx
   jne     1f

   xor     %rax, %rax
   pop     %rbp
   retq

1: mov     %edi, %eax  /* EAX == oldValue */

   lock
   cmpxchg %esi, (%rdx)

   setz    %al
   pop     %rbp
   retq

/* Boolean OSCompareAndSwap64(UInt64 oldValue, UInt64 newValue,
 *                            volatile UInt64 *address);
 * Boolean OSCompareAndSwapPtr(void *oldValue, void *newValue,
 *                             void * volatile *address);
 *
 * Called with:
 *
 *   RDI == oldValue
 *   RSI == newValue
 *   RDX == address
 */
Entry(OSCompareAndSwap64_fixed)
Entry(OSCompareAndSwapPtr_fixed)
   push    %rbp
   mov     %rsp, %rbp

   cmp     $0, %rdx
   jne     1f

   xor     %rax, %rax
   pop     %rbp
   retq

1: mov     %rdi, %rax  /* RAX == oldValue */

   lock
   cmpxchg %rsi, (%rdx)

   setz    %al
   pop     %rbp
   retq

/* Boolean OSCompareAndSwap128(__uint128_t oldValue, __uint128_t newValue,
 *                             volatile __uint128_t *address);
 *
 * Called with:
 *
 *   RSI:RDI == oldValue (RSI is high qword)
 *   RCX:RDX == newValue (RCX is high qword)
 *   R8      == address
 *
 * 'address' (R8) must be 16-byte aligned.
 */
Entry(OSCompareAndSwap128)
   push    %rbp
   mov     %rsp, %rbp
   push    %rbx

   cmp     $0, %r8
   jne     1f

   xor     %rax, %rax
   pop     %rbx
   pop     %rbp
   retq

1: mov     %rdx, %rbx  /* RCX:RBX == newValue */
   mov     %rsi, %rdx
   mov     %rdi, %rax  /* RDX:RAX == oldValue */

   lock
   cmpxchg16b (%r8)

   setz    %al
   pop     %rbx
   pop     %rbp
   retq

