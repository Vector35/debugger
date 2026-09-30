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
.p2align 4
_main:
    pushq %rbp
    movq %rsp, %rbp
_native_call:
    callq native_callee
_native_after_call:
_native_store:
    movq %rax, _native_value(%rip)
    xorl %eax, %eax
    popq %rbp
    retq
native_callee:
    pushq %rbp
    movq %rsp, %rbp
_native_body:
    movl $42, %eax
    popq %rbp
    retq
.data
.globl _native_value
.p2align 3
_native_value:
    .quad 0
