/*
Copyright 2020-2026 Vector 35 Inc.

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

.text
.globl _main
.globl _native_call
.globl _native_after_call
.globl _native_body
.globl _native_store
.p2align 2
_main:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
_native_call:
    bl native_callee
_native_after_call:
    adrp x9, _native_value@PAGE
    add x9, x9, _native_value@PAGEOFF
_native_store:
    str w0, [x9]
    mov w0, #0
    ldp x29, x30, [sp], #16
    ret
native_callee:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
_native_body:
    mov w0, #42
    ldp x29, x30, [sp], #16
    ret
.data
.globl _native_value
.p2align 3
_native_value:
    .quad 0
