# 
# Whirlpool hash in x86 assembly
# 
# Copyright (c) 2014 Project Nayuki
# http://www.nayuki.io/page/fast-whirlpool-hash-in-x86-assembly
# 
# (MIT License)
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
#

# Modified by kerukuro for use in cppcrypto.

# 1 "whirlpool.S"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "whirlpool.S"
# 28 "whirlpool.S"
.globl _whirlpool_compress_asm
.globl whirlpool_compress_asm
_whirlpool_compress_asm:
whirlpool_compress_asm:
# 83 "whirlpool.S"
 pushl %ebx
 pushl %esi
 movl 12(%esp), %edx
 movl 16(%esp), %esi
 subl $8, %esp


 movdqu 0(%edx), %xmm0
 movdqu 16(%edx), %xmm1
 movdqu 32(%edx), %xmm2
 movdqu 48(%edx), %xmm3


 movdqu 0(%esi), %xmm4
 movdqu 16(%esi), %xmm5
 movdqu 32(%esi), %xmm6
 movdqu 48(%esi), %xmm7


 pxor %xmm0, %xmm4; pxor %xmm1, %xmm5; pxor %xmm2, %xmm6; pxor %xmm3, %xmm7;


 movl $0, %ecx
.looptop:


 pextrw $(0), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm0; movq .magictable1(,%ebx,8), %mm1;
 pextrw $(0), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm2; movq .magictable1(,%ebx,8), %mm3;
 pextrw $(0), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm4; movq .magictable1(,%ebx,8), %mm5;
 pextrw $(0), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm6; movq .magictable1(,%ebx,8), %mm7;
 pextrw $(4), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(4), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(4), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(4), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(1), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(1), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(1), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(1), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(5), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(5), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(5), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(5), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(2), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(2), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(2), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(2), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(6), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(6), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(6), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(6), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(3), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(3), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(3), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(3), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(7), %xmm1, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(7), %xmm2, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(7), %xmm3, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(7), %xmm0, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pxor .roundconstants(,%ecx,8), %mm0


 movq %mm7, (%esp)
 movq2dq %mm0, %xmm0; movq2dq %mm1, %xmm1; shufpd $0, %xmm1, %xmm0
 movq2dq %mm2, %xmm1; movq2dq %mm3, %xmm2; shufpd $0, %xmm2, %xmm1
 movq2dq %mm4, %xmm2; movq2dq %mm5, %xmm3; shufpd $0, %xmm3, %xmm2
 movq2dq %mm6, %xmm3; movhps (%esp), %xmm3


 pextrw $(0), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm0; movq .magictable1(,%ebx,8), %mm1;
 pextrw $(0), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm2; movq .magictable1(,%ebx,8), %mm3;
 pextrw $(0), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm4; movq .magictable1(,%ebx,8), %mm5;
 pextrw $(0), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; movq .magictable0(,%eax,8), %mm6; movq .magictable1(,%ebx,8), %mm7;
 pextrw $(4), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(4), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(4), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(4), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(1), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(1), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(1), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(1), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(5), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(5), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(5), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(5), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(2), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(2), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(2), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(2), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(6), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(6), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(6), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(6), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;
 pextrw $(3), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm0; pxor .magictable1(,%ebx,8), %mm1;
 pextrw $(3), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm2; pxor .magictable1(,%ebx,8), %mm3;
 pextrw $(3), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm4; pxor .magictable1(,%ebx,8), %mm5;
 pextrw $(3), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm6; pxor .magictable1(,%ebx,8), %mm7;
 pextrw $(7), %xmm5, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm1; pxor .magictable1(,%ebx,8), %mm2;
 pextrw $(7), %xmm6, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm3; pxor .magictable1(,%ebx,8), %mm4;
 pextrw $(7), %xmm7, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm5; pxor .magictable1(,%ebx,8), %mm6;
 pextrw $(7), %xmm4, %eax; movzbl %ah, %ebx; andl $0xFF, %eax; pxor .magictable0(,%eax,8), %mm7; pxor .magictable1(,%ebx,8), %mm0;
 pshufw $0x39, %mm0, %mm0; pshufw $0x39, %mm1, %mm1; pshufw $0x39, %mm2, %mm2; pshufw $0x39, %mm3, %mm3; pshufw $0x39, %mm4, %mm4; pshufw $0x39, %mm5, %mm5; pshufw $0x39, %mm6, %mm6; pshufw $0x39, %mm7, %mm7;


 movq %mm7, (%esp)
 movq2dq %mm0, %xmm4; movq2dq %mm1, %xmm5; shufpd $0, %xmm5, %xmm4
 movq2dq %mm2, %xmm5; movq2dq %mm3, %xmm6; shufpd $0, %xmm6, %xmm5
 movq2dq %mm4, %xmm6; movq2dq %mm5, %xmm7; shufpd $0, %xmm7, %xmm6
 movq2dq %mm6, %xmm7; movhps (%esp), %xmm7


 pxor %xmm0, %xmm4; pxor %xmm1, %xmm5; pxor %xmm2, %xmm6; pxor %xmm3, %xmm7;


 incl %ecx
 cmpl $10, %ecx
 jne .looptop


 movdqu 0(%edx), %xmm0
 movdqu 16(%edx), %xmm1
 movdqu 32(%edx), %xmm2
 movdqu 48(%edx), %xmm3
 pxor %xmm0, %xmm4; pxor %xmm1, %xmm5; pxor %xmm2, %xmm6; pxor %xmm3, %xmm7;
 movdqu 0(%esi), %xmm0
 movdqu 16(%esi), %xmm1
 movdqu 32(%esi), %xmm2
 movdqu 48(%esi), %xmm3
 pxor %xmm0, %xmm4; pxor %xmm1, %xmm5; pxor %xmm2, %xmm6; pxor %xmm3, %xmm7;
 movdqu %xmm4, 0(%edx)
 movdqu %xmm5, 16(%edx)
 movdqu %xmm6, 32(%edx)
 movdqu %xmm7, 48(%edx)


 emms
 addl $8, %esp
 popl %esi
 popl %ebx
 retl


.balign 8
.roundconstants:
.byte 0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52
.byte 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57
.byte 0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85
.byte 0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8
.byte 0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33
.byte 0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0
.byte 0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE
.byte 0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D
.byte 0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF
.byte 0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A
.byte 0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C
.byte 0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04
.byte 0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB
.byte 0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9
.byte 0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1
.byte 0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86

.magictable0:
.quad 0xD83078C018601818, 0x2646AF05238C2323, 0xB891F97EC63FC6C6, 0xFBCD6F13E887E8E8, 0xCB13A14C87268787, 0x116D62A9B8DAB8B8, 0x0902050801040101, 0x0D9E6E424F214F4F
.quad 0x9B6CEEAD36D83636, 0xFF510459A6A2A6A6, 0x0CB9BDDED26FD2D2, 0x0EF706FBF5F3F5F5, 0x96F280EF79F97979, 0x30DECE5F6FA16F6F, 0x6D3FEFFC917E9191, 0xF8A407AA52555252
.quad 0x47C0FD27609D6060, 0x35657689BCCABCBC, 0x372BCDAC9B569B9B, 0x8A018C048E028E8E, 0xD25B1571A3B6A3A3, 0x6C183C600C300C0C, 0x84F68AFF7BF17B7B, 0x806AE1B535D43535
.quad 0xF53A69E81D741D1D, 0xB3DD4753E0A7E0E0, 0x21B3ACF6D77BD7D7, 0x9C99ED5EC22FC2C2, 0x435C966D2EB82E2E, 0x29967A624B314B4B, 0x5DE121A3FEDFFEFE, 0xD5AE168257415757
.quad 0xBD2A41A815541515, 0xE8EEB69F77C17777, 0x926EEBA537DC3737, 0x9ED7567BE5B3E5E5, 0x1323D98C9F469F9F, 0x23FD17D3F0E7F0F0, 0x20947F6A4A354A4A, 0x44A9959EDA4FDADA
.quad 0xA2B025FA587D5858, 0xCF8FCA06C903C9C9, 0x7C528D5529A42929, 0x5A1422500A280A0A, 0x507F4FE1B1FEB1B1, 0xC95D1A69A0BAA0A0, 0x14D6DA7F6BB16B6B, 0xD917AB5C852E8585
.quad 0x3C677381BDCEBDBD, 0x8FBA34D25D695D5D, 0x9020508010401010, 0x07F503F3F4F7F4F4, 0xDD8BC016CB0BCBCB, 0xD37CC6ED3EF83E3E, 0x2D0A112805140505, 0x78CEE61F67816767
.quad 0x97D55373E4B7E4E4, 0x024EBB25279C2727, 0x7382583241194141, 0xA70B9D2C8B168B8B, 0xF6530151A7A6A7A7, 0xB2FA94CF7DE97D7D, 0x4937FBDC956E9595, 0x56AD9F8ED847D8D8
.quad 0x70EB308BFBCBFBFB, 0xCDC17123EE9FEEEE, 0xBBF891C77CED7C7C, 0x71CCE31766856666, 0x7BA78EA6DD53DDDD, 0xAF2E4BB8175C1717, 0x458E460247014747, 0x1A21DC849E429E9E
.quad 0xD489C51ECA0FCACA, 0x585A99752DB42D2D, 0x2E637991BFC6BFBF, 0x3F0E1B38071C0707, 0xAC472301AD8EADAD, 0xB0B42FEA5A755A5A, 0xEF1BB56C83368383, 0xB666FF8533CC3333
.quad 0x5CC6F23F63916363, 0x12040A1002080202, 0x93493839AA92AAAA, 0xDEE2A8AF71D97171, 0xC68DCF0EC807C8C8, 0xD1327DC819641919, 0x3B92707249394949, 0x5FAF9A86D943D9D9
.quad 0x31F91DC3F2EFF2F2, 0xA8DB484BE3ABE3E3, 0xB9B62AE25B715B5B, 0xBC0D9234881A8888, 0x3E29C8A49A529A9A, 0x0B4CBE2D26982626, 0xBF64FA8D32C83232, 0x597D4AE9B0FAB0B0
.quad 0xF2CF6A1BE983E9E9, 0x771E33780F3C0F0F, 0x33B7A6E6D573D5D5, 0xF41DBA74803A8080, 0x27617C99BEC2BEBE, 0xEB87DE26CD13CDCD, 0x8968E4BD34D03434, 0x3290757A483D4848
.quad 0x54E324ABFFDBFFFF, 0x8DF48FF77AF57A7A, 0x643DEAF4907A9090, 0x9DBE3EC25F615F5F, 0x3D40A01D20802020, 0x0FD0D56768BD6868, 0xCA3472D01A681A1A, 0xB7412C19AE82AEAE
.quad 0x7D755EC9B4EAB4B4, 0xCEA8199A544D5454, 0x7F3BE5EC93769393, 0x2F44AA0D22882222, 0x63C8E907648D6464, 0x2AFF12DBF1E3F1F1, 0xCCE6A2BF73D17373, 0x82245A9012481212
.quad 0x7A805D3A401D4040, 0x4810284008200808, 0x959BE856C32BC3C3, 0xDFC57B33EC97ECEC, 0x4DAB9096DB4BDBDB, 0xC05F1F61A1BEA1A1, 0x9107831C8D0E8D8D, 0xC87AC9F53DF43D3D
.quad 0x5B33F1CC97669797, 0x0000000000000000, 0xF983D436CF1BCFCF, 0x6E5687452BAC2B2B, 0xE1ECB39776C57676, 0xE619B06482328282, 0x28B1A9FED67FD6D6, 0xC33677D81B6C1B1B
.quad 0x74775BC1B5EEB5B5, 0xBE432911AF86AFAF, 0x1DD4DF776AB56A6A, 0xEAA00DBA505D5050, 0x578A4C1245094545, 0x38FB18CBF3EBF3F3, 0xAD60F09D30C03030, 0xC4C3742BEF9BEFEF
.quad 0xDA7EC3E53FFC3F3F, 0xC7AA1C9255495555, 0xDB591079A2B2A2A2, 0xE9C96503EA8FEAEA, 0x6ACAEC0F65896565, 0x036968B9BAD2BABA, 0x4A5E93652FBC2F2F, 0x8E9DE74EC027C0C0
.quad 0x60A181BEDE5FDEDE, 0xFC386CE01C701C1C, 0x46E72EBBFDD3FDFD, 0x1F9A64524D294D4D, 0x7639E0E492729292, 0xFAEABC8F75C97575, 0x360C1E3006180606, 0xAE0998248A128A8A
.quad 0x4B7940F9B2F2B2B2, 0x85D15963E6BFE6E6, 0x7E1C36700E380E0E, 0xE73E63F81F7C1F1F, 0x55C4F73762956262, 0x3AB5A3EED477D4D4, 0x814D3229A89AA8A8, 0x5231F4C496629696
.quad 0x62EF3A9BF9C3F9F9, 0xA397F666C533C5C5, 0x104AB13525942525, 0xABB220F259795959, 0xD015AE54842A8484, 0xC5E4A7B772D57272, 0xEC72DDD539E43939, 0x1698615A4C2D4C4C
.quad 0x94BC3BCA5E655E5E, 0x9FF085E778FD7878, 0xE570D8DD38E03838, 0x980586148C0A8C8C, 0x17BFB2C6D163D1D1, 0xE4570B41A5AEA5A5, 0xA1D94D43E2AFE2E2, 0x4EC2F82F61996161
.quad 0x427B45F1B3F6B3B3, 0x3442A51521842121, 0x0825D6949C4A9C9C, 0xEE3C66F01E781E1E, 0x6186522243114343, 0xB193FC76C73BC7C7, 0x4FE52BB3FCD7FCFC, 0x2408142004100404
.quad 0xE3A208B251595151, 0x252FC7BC995E9999, 0x22DAC44F6DA96D6D, 0x651A39680D340D0D, 0x79E93583FACFFAFA, 0x69A384B6DF5BDFDF, 0xA9FC9BD77EE57E7E, 0x1948B43D24902424
.quad 0xFE76D7C53BEC3B3B, 0x9A4B3D31AB96ABAB, 0xF081D13ECE1FCECE, 0x9922558811441111, 0x8303890C8F068F8F, 0x049C6B4A4E254E4E, 0x667351D1B7E6B7B7, 0xE0CB600BEB8BEBEB
.quad 0xC178CCFD3CF03C3C, 0xFD1FBF7C813E8181, 0x4035FED4946A9494, 0x1CF30CEBF7FBF7F7, 0x186F67A1B9DEB9B9, 0x8B265F98134C1313, 0x51589C7D2CB02C2C, 0x05BBB8D6D36BD3D3
.quad 0x8CD35C6BE7BBE7E7, 0x39DCCB576EA56E6E, 0xAA95F36EC437C4C4, 0x1B060F18030C0303, 0xDCAC138A56455656, 0x5E88491A440D4444, 0xA0FE9EDF7FE17F7F, 0x884F3721A99EA9A9
.quad 0x6754824D2AA82A2A, 0x0A6B6DB1BBD6BBBB, 0x879FE246C123C1C1, 0xF1A602A253515353, 0x72A58BAEDC57DCDC, 0x531627580B2C0B0B, 0x0127D39C9D4E9D9D, 0x2BD8C1476CAD6C6C
.quad 0xA462F59531C43131, 0xF3E8B98774CD7474, 0x15F109E3F6FFF6F6, 0x4C8C430A46054646, 0xA5452609AC8AACAC, 0xB50F973C891E8989, 0xB42844A014501414, 0xBADF425BE1A3E1E1
.quad 0xA62C4EB016581616, 0xF774D2CD3AE83A3A, 0x06D2D06F69B96969, 0x41122D4809240909, 0xD7E0ADA770DD7070, 0x6F7154D9B6E2B6B6, 0x1EBDB7CED067D0D0, 0xD6C77E3BED93EDED
.quad 0xE285DB2ECC17CCCC, 0x6884572A42154242, 0x2C2DC2B4985A9898, 0xED550E49A4AAA4A4, 0x7550885D28A02828, 0x86B831DA5C6D5C5C, 0x6BED3F93F8C7F8F8, 0xC211A44486228686
.magictable1:
.quad 0x3078C018601818D8, 0x46AF05238C232326, 0x91F97EC63FC6C6B8, 0xCD6F13E887E8E8FB, 0x13A14C87268787CB, 0x6D62A9B8DAB8B811, 0x0205080104010109, 0x9E6E424F214F4F0D
.quad 0x6CEEAD36D836369B, 0x510459A6A2A6A6FF, 0xB9BDDED26FD2D20C, 0xF706FBF5F3F5F50E, 0xF280EF79F9797996, 0xDECE5F6FA16F6F30, 0x3FEFFC917E91916D, 0xA407AA52555252F8
.quad 0xC0FD27609D606047, 0x657689BCCABCBC35, 0x2BCDAC9B569B9B37, 0x018C048E028E8E8A, 0x5B1571A3B6A3A3D2, 0x183C600C300C0C6C, 0xF68AFF7BF17B7B84, 0x6AE1B535D4353580
.quad 0x3A69E81D741D1DF5, 0xDD4753E0A7E0E0B3, 0xB3ACF6D77BD7D721, 0x99ED5EC22FC2C29C, 0x5C966D2EB82E2E43, 0x967A624B314B4B29, 0xE121A3FEDFFEFE5D, 0xAE168257415757D5
.quad 0x2A41A815541515BD, 0xEEB69F77C17777E8, 0x6EEBA537DC373792, 0xD7567BE5B3E5E59E, 0x23D98C9F469F9F13, 0xFD17D3F0E7F0F023, 0x947F6A4A354A4A20, 0xA9959EDA4FDADA44
.quad 0xB025FA587D5858A2, 0x8FCA06C903C9C9CF, 0x528D5529A429297C, 0x1422500A280A0A5A, 0x7F4FE1B1FEB1B150, 0x5D1A69A0BAA0A0C9, 0xD6DA7F6BB16B6B14, 0x17AB5C852E8585D9
.quad 0x677381BDCEBDBD3C, 0xBA34D25D695D5D8F, 0x2050801040101090, 0xF503F3F4F7F4F407, 0x8BC016CB0BCBCBDD, 0x7CC6ED3EF83E3ED3, 0x0A1128051405052D, 0xCEE61F6781676778
.quad 0xD55373E4B7E4E497, 0x4EBB25279C272702, 0x8258324119414173, 0x0B9D2C8B168B8BA7, 0x530151A7A6A7A7F6, 0xFA94CF7DE97D7DB2, 0x37FBDC956E959549, 0xAD9F8ED847D8D856
.quad 0xEB308BFBCBFBFB70, 0xC17123EE9FEEEECD, 0xF891C77CED7C7CBB, 0xCCE3176685666671, 0xA78EA6DD53DDDD7B, 0x2E4BB8175C1717AF, 0x8E46024701474745, 0x21DC849E429E9E1A
.quad 0x89C51ECA0FCACAD4, 0x5A99752DB42D2D58, 0x637991BFC6BFBF2E, 0x0E1B38071C07073F, 0x472301AD8EADADAC, 0xB42FEA5A755A5AB0, 0x1BB56C83368383EF, 0x66FF8533CC3333B6
.quad 0xC6F23F639163635C, 0x040A100208020212, 0x493839AA92AAAA93, 0xE2A8AF71D97171DE, 0x8DCF0EC807C8C8C6, 0x327DC819641919D1, 0x927072493949493B, 0xAF9A86D943D9D95F
.quad 0xF91DC3F2EFF2F231, 0xDB484BE3ABE3E3A8, 0xB62AE25B715B5BB9, 0x0D9234881A8888BC, 0x29C8A49A529A9A3E, 0x4CBE2D269826260B, 0x64FA8D32C83232BF, 0x7D4AE9B0FAB0B059
.quad 0xCF6A1BE983E9E9F2, 0x1E33780F3C0F0F77, 0xB7A6E6D573D5D533, 0x1DBA74803A8080F4, 0x617C99BEC2BEBE27, 0x87DE26CD13CDCDEB, 0x68E4BD34D0343489, 0x90757A483D484832
.quad 0xE324ABFFDBFFFF54, 0xF48FF77AF57A7A8D, 0x3DEAF4907A909064, 0xBE3EC25F615F5F9D, 0x40A01D208020203D, 0xD0D56768BD68680F, 0x3472D01A681A1ACA, 0x412C19AE82AEAEB7
.quad 0x755EC9B4EAB4B47D, 0xA8199A544D5454CE, 0x3BE5EC937693937F, 0x44AA0D228822222F, 0xC8E907648D646463, 0xFF12DBF1E3F1F12A, 0xE6A2BF73D17373CC, 0x245A901248121282
.quad 0x805D3A401D40407A, 0x1028400820080848, 0x9BE856C32BC3C395, 0xC57B33EC97ECECDF, 0xAB9096DB4BDBDB4D, 0x5F1F61A1BEA1A1C0, 0x07831C8D0E8D8D91, 0x7AC9F53DF43D3DC8
.quad 0x33F1CC976697975B, 0x0000000000000000, 0x83D436CF1BCFCFF9, 0x5687452BAC2B2B6E, 0xECB39776C57676E1, 0x19B06482328282E6, 0xB1A9FED67FD6D628, 0x3677D81B6C1B1BC3
.quad 0x775BC1B5EEB5B574, 0x432911AF86AFAFBE, 0xD4DF776AB56A6A1D, 0xA00DBA505D5050EA, 0x8A4C124509454557, 0xFB18CBF3EBF3F338, 0x60F09D30C03030AD, 0xC3742BEF9BEFEFC4
.quad 0x7EC3E53FFC3F3FDA, 0xAA1C9255495555C7, 0x591079A2B2A2A2DB, 0xC96503EA8FEAEAE9, 0xCAEC0F658965656A, 0x6968B9BAD2BABA03, 0x5E93652FBC2F2F4A, 0x9DE74EC027C0C08E
.quad 0xA181BEDE5FDEDE60, 0x386CE01C701C1CFC, 0xE72EBBFDD3FDFD46, 0x9A64524D294D4D1F, 0x39E0E49272929276, 0xEABC8F75C97575FA, 0x0C1E300618060636, 0x0998248A128A8AAE
.quad 0x7940F9B2F2B2B24B, 0xD15963E6BFE6E685, 0x1C36700E380E0E7E, 0x3E63F81F7C1F1FE7, 0xC4F7376295626255, 0xB5A3EED477D4D43A, 0x4D3229A89AA8A881, 0x31F4C49662969652
.quad 0xEF3A9BF9C3F9F962, 0x97F666C533C5C5A3, 0x4AB1352594252510, 0xB220F259795959AB, 0x15AE54842A8484D0, 0xE4A7B772D57272C5, 0x72DDD539E43939EC, 0x98615A4C2D4C4C16
.quad 0xBC3BCA5E655E5E94, 0xF085E778FD78789F, 0x70D8DD38E03838E5, 0x0586148C0A8C8C98, 0xBFB2C6D163D1D117, 0x570B41A5AEA5A5E4, 0xD94D43E2AFE2E2A1, 0xC2F82F619961614E
.quad 0x7B45F1B3F6B3B342, 0x42A5152184212134, 0x25D6949C4A9C9C08, 0x3C66F01E781E1EEE, 0x8652224311434361, 0x93FC76C73BC7C7B1, 0xE52BB3FCD7FCFC4F, 0x0814200410040424
.quad 0xA208B251595151E3, 0x2FC7BC995E999925, 0xDAC44F6DA96D6D22, 0x1A39680D340D0D65, 0xE93583FACFFAFA79, 0xA384B6DF5BDFDF69, 0xFC9BD77EE57E7EA9, 0x48B43D2490242419
.quad 0x76D7C53BEC3B3BFE, 0x4B3D31AB96ABAB9A, 0x81D13ECE1FCECEF0, 0x2255881144111199, 0x03890C8F068F8F83, 0x9C6B4A4E254E4E04, 0x7351D1B7E6B7B766, 0xCB600BEB8BEBEBE0
.quad 0x78CCFD3CF03C3CC1, 0x1FBF7C813E8181FD, 0x35FED4946A949440, 0xF30CEBF7FBF7F71C, 0x6F67A1B9DEB9B918, 0x265F98134C13138B, 0x589C7D2CB02C2C51, 0xBBB8D6D36BD3D305
.quad 0xD35C6BE7BBE7E78C, 0xDCCB576EA56E6E39, 0x95F36EC437C4C4AA, 0x060F18030C03031B, 0xAC138A56455656DC, 0x88491A440D44445E, 0xFE9EDF7FE17F7FA0, 0x4F3721A99EA9A988
.quad 0x54824D2AA82A2A67, 0x6B6DB1BBD6BBBB0A, 0x9FE246C123C1C187, 0xA602A253515353F1, 0xA58BAEDC57DCDC72, 0x1627580B2C0B0B53, 0x27D39C9D4E9D9D01, 0xD8C1476CAD6C6C2B
.quad 0x62F59531C43131A4, 0xE8B98774CD7474F3, 0xF109E3F6FFF6F615, 0x8C430A460546464C, 0x452609AC8AACACA5, 0x0F973C891E8989B5, 0x2844A014501414B4, 0xDF425BE1A3E1E1BA
.quad 0x2C4EB016581616A6, 0x74D2CD3AE83A3AF7, 0xD2D06F69B9696906, 0x122D480924090941, 0xE0ADA770DD7070D7, 0x7154D9B6E2B6B66F, 0xBDB7CED067D0D01E, 0xC77E3BED93EDEDD6
.quad 0x85DB2ECC17CCCCE2, 0x84572A4215424268, 0x2DC2B4985A98982C, 0x550E49A4AAA4A4ED, 0x50885D28A0282875, 0xB831DA5C6D5C5C86, 0xED3F93F8C7F8F86B, 0x11A44486228686C2
