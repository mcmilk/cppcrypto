; This implementation is taken from Crypto++ library.
; Author: Wei Dai.
; This code is placed in the public domain.

; Modified by kerukuro for use in cppcrypto.

include ksamd64.inc
EXTERNDEF ?SHA256_K@cppcrypto@@3QBIB:FAR
.CODE

ALIGN   8
X86_SHA256_HashBlocks	PROC FRAME
rex_push_reg rsi
push_reg rdi
push_reg rbx
push_reg rbp
alloc_stack(8*4 + 16*4 + 4*8 + 8)
.endprolog
mov rdi, r8
lea rsi, [?SHA256_K@cppcrypto@@3QBIB + 48*4]
mov [rsp+8*4+16*4+1*8], rcx
mov [rsp+8*4+16*4+2*8], rdx
add rdi, rdx
mov [rsp+8*4+16*4+3*8], rdi
movdqa xmm0, XMMWORD PTR [rcx+0*16]
movdqa xmm1, XMMWORD PTR [rcx+1*16]
mov [rsp+8*4+16*4+0*8], rsi
label0:
sub rsi, 48*4
movdqa [rsp+((1024+7-(0+3)) MOD (8))*4], xmm1
movdqa [rsp+((1024+7-(0+7)) MOD (8))*4], xmm0
mov rbx, [rdx+0*8]
bswap rbx
mov [rsp+8*4+((1024+15-(0*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+1*8]
bswap rbx
mov [rsp+8*4+((1024+15-(1*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+2*8]
bswap rbx
mov [rsp+8*4+((1024+15-(2*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+3*8]
bswap rbx
mov [rsp+8*4+((1024+15-(3*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+4*8]
bswap rbx
mov [rsp+8*4+((1024+15-(4*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+5*8]
bswap rbx
mov [rsp+8*4+((1024+15-(5*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+6*8]
bswap rbx
mov [rsp+8*4+((1024+15-(6*(1+1)+1)) MOD (16))*4], rbx
mov rbx, [rdx+7*8]
bswap rbx
mov [rsp+8*4+((1024+15-(7*(1+1)+1)) MOD (16))*4], rbx
mov edi, [rsp+((1024+7-(0+3)) MOD (8))*4]
mov eax, [rsp+((1024+7-(0+6)) MOD (8))*4]
xor eax, [rsp+((1024+7-(0+5)) MOD (8))*4]
mov ecx, [rsp+((1024+7-(0+7)) MOD (8))*4]
mov edx, [rsp+((1024+7-(0+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(0+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(0+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(0)*4]
add edx, [rsp+8*4+((1024+15-(0)) MOD (16))*4]
add edx, [rsp+((1024+7-(0)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(0+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(0+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(0+4)) MOD (8))*4]
mov [rsp+((1024+7-(0+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(0)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(1+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(1+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(1+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(1)*4]
add edi, [rsp+8*4+((1024+15-(1)) MOD (16))*4]
add edi, [rsp+((1024+7-(1)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(1+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(1+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(1+4)) MOD (8))*4]
mov [rsp+((1024+7-(1+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(1)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(2+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(2+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(2+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(2)*4]
add edx, [rsp+8*4+((1024+15-(2)) MOD (16))*4]
add edx, [rsp+((1024+7-(2)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(2+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(2+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(2+4)) MOD (8))*4]
mov [rsp+((1024+7-(2+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(2)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(3+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(3+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(3+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(3)*4]
add edi, [rsp+8*4+((1024+15-(3)) MOD (16))*4]
add edi, [rsp+((1024+7-(3)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(3+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(3+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(3+4)) MOD (8))*4]
mov [rsp+((1024+7-(3+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(3)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(4+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(4+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(4+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(4)*4]
add edx, [rsp+8*4+((1024+15-(4)) MOD (16))*4]
add edx, [rsp+((1024+7-(4)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(4+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(4+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(4+4)) MOD (8))*4]
mov [rsp+((1024+7-(4+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(4)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(5+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(5+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(5+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(5)*4]
add edi, [rsp+8*4+((1024+15-(5)) MOD (16))*4]
add edi, [rsp+((1024+7-(5)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(5+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(5+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(5+4)) MOD (8))*4]
mov [rsp+((1024+7-(5+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(5)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(6+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(6+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(6+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(6)*4]
add edx, [rsp+8*4+((1024+15-(6)) MOD (16))*4]
add edx, [rsp+((1024+7-(6)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(6+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(6+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(6+4)) MOD (8))*4]
mov [rsp+((1024+7-(6+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(6)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(7+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(7+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(7+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(7)*4]
add edi, [rsp+8*4+((1024+15-(7)) MOD (16))*4]
add edi, [rsp+((1024+7-(7)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(7+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(7+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(7+4)) MOD (8))*4]
mov [rsp+((1024+7-(7+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(7)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(8+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(8+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(8+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(8)*4]
add edx, [rsp+8*4+((1024+15-(8)) MOD (16))*4]
add edx, [rsp+((1024+7-(8)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(8+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(8+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(8+4)) MOD (8))*4]
mov [rsp+((1024+7-(8+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(8)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(9+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(9+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(9+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(9)*4]
add edi, [rsp+8*4+((1024+15-(9)) MOD (16))*4]
add edi, [rsp+((1024+7-(9)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(9+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(9+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(9+4)) MOD (8))*4]
mov [rsp+((1024+7-(9+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(9)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(10+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(10+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(10+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(10)*4]
add edx, [rsp+8*4+((1024+15-(10)) MOD (16))*4]
add edx, [rsp+((1024+7-(10)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(10+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(10+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(10+4)) MOD (8))*4]
mov [rsp+((1024+7-(10+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(10)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(11+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(11+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(11+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(11)*4]
add edi, [rsp+8*4+((1024+15-(11)) MOD (16))*4]
add edi, [rsp+((1024+7-(11)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(11+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(11+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(11+4)) MOD (8))*4]
mov [rsp+((1024+7-(11+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(11)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(12+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(12+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(12+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(12)*4]
add edx, [rsp+8*4+((1024+15-(12)) MOD (16))*4]
add edx, [rsp+((1024+7-(12)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(12+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(12+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(12+4)) MOD (8))*4]
mov [rsp+((1024+7-(12+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(12)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(13+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(13+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(13+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(13)*4]
add edi, [rsp+8*4+((1024+15-(13)) MOD (16))*4]
add edi, [rsp+((1024+7-(13)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(13+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(13+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(13+4)) MOD (8))*4]
mov [rsp+((1024+7-(13+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(13)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(14+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(14+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(14+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
add edx, [rsi+(14)*4]
add edx, [rsp+8*4+((1024+15-(14)) MOD (16))*4]
add edx, [rsp+((1024+7-(14)) MOD (8))*4]
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(14+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(14+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(14+4)) MOD (8))*4]
mov [rsp+((1024+7-(14+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(14)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(15+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(15+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(15+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
add edi, [rsi+(15)*4]
add edi, [rsp+8*4+((1024+15-(15)) MOD (16))*4]
add edi, [rsp+((1024+7-(15)) MOD (8))*4]
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(15+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(15+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(15+4)) MOD (8))*4]
mov [rsp+((1024+7-(15+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(15)) MOD (8))*4], ecx
label1:
add rsi, 4*16
mov edx, [rsp+((1024+7-(0+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(0+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(0+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((0)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((0)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((0)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(0)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(0)*4]
ror edi, 11
add edx, [rsp+((1024+7-(0)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(0)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(0+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(0+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(0+4)) MOD (8))*4]
mov [rsp+((1024+7-(0+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(0)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(1+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(1+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(1+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((1)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((1)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((1)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(1)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(1)*4]
ror edx, 11
add edi, [rsp+((1024+7-(1)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(1)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(1+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(1+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(1+4)) MOD (8))*4]
mov [rsp+((1024+7-(1+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(1)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(2+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(2+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(2+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((2)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((2)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((2)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(2)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(2)*4]
ror edi, 11
add edx, [rsp+((1024+7-(2)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(2)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(2+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(2+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(2+4)) MOD (8))*4]
mov [rsp+((1024+7-(2+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(2)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(3+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(3+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(3+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((3)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((3)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((3)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(3)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(3)*4]
ror edx, 11
add edi, [rsp+((1024+7-(3)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(3)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(3+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(3+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(3+4)) MOD (8))*4]
mov [rsp+((1024+7-(3+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(3)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(4+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(4+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(4+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((4)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((4)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((4)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(4)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(4)*4]
ror edi, 11
add edx, [rsp+((1024+7-(4)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(4)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(4+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(4+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(4+4)) MOD (8))*4]
mov [rsp+((1024+7-(4+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(4)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(5+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(5+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(5+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((5)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((5)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((5)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(5)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(5)*4]
ror edx, 11
add edi, [rsp+((1024+7-(5)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(5)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(5+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(5+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(5+4)) MOD (8))*4]
mov [rsp+((1024+7-(5+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(5)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(6+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(6+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(6+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((6)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((6)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((6)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(6)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(6)*4]
ror edi, 11
add edx, [rsp+((1024+7-(6)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(6)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(6+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(6+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(6+4)) MOD (8))*4]
mov [rsp+((1024+7-(6+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(6)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(7+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(7+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(7+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((7)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((7)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((7)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(7)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(7)*4]
ror edx, 11
add edi, [rsp+((1024+7-(7)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(7)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(7+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(7+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(7+4)) MOD (8))*4]
mov [rsp+((1024+7-(7+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(7)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(8+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(8+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(8+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((8)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((8)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((8)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(8)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(8)*4]
ror edi, 11
add edx, [rsp+((1024+7-(8)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(8)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(8+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(8+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(8+4)) MOD (8))*4]
mov [rsp+((1024+7-(8+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(8)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(9+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(9+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(9+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((9)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((9)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((9)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(9)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(9)*4]
ror edx, 11
add edi, [rsp+((1024+7-(9)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(9)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(9+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(9+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(9+4)) MOD (8))*4]
mov [rsp+((1024+7-(9+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(9)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(10+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(10+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(10+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((10)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((10)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((10)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(10)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(10)*4]
ror edi, 11
add edx, [rsp+((1024+7-(10)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(10)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(10+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(10+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(10+4)) MOD (8))*4]
mov [rsp+((1024+7-(10+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(10)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(11+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(11+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(11+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((11)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((11)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((11)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(11)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(11)*4]
ror edx, 11
add edi, [rsp+((1024+7-(11)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(11)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(11+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(11+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(11+4)) MOD (8))*4]
mov [rsp+((1024+7-(11+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(11)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(12+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(12+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(12+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((12)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((12)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((12)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(12)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(12)*4]
ror edi, 11
add edx, [rsp+((1024+7-(12)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(12)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(12+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(12+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(12+4)) MOD (8))*4]
mov [rsp+((1024+7-(12+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(12)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(13+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(13+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(13+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((13)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((13)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((13)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(13)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(13)*4]
ror edx, 11
add edi, [rsp+((1024+7-(13)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(13)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(13+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(13+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(13+4)) MOD (8))*4]
mov [rsp+((1024+7-(13+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(13)) MOD (8))*4], ecx
mov edx, [rsp+((1024+7-(14+2)) MOD (8))*4]
xor edx, [rsp+((1024+7-(14+1)) MOD (8))*4]
and edx, edi
xor edx, [rsp+((1024+7-(14+1)) MOD (8))*4]
mov ebp, edi
ror edi, 6
ror ebp, 25
xor ebp, edi
ror edi, 5
xor ebp, edi
add edx, ebp
mov ebp, [rsp+8*4+((1024+15-((14)-2)) MOD (16))*4]
mov edi, [rsp+8*4+((1024+15-((14)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((14)-7)) MOD (16))*4]
mov ebp, edi
shr ebp, 3
ror edi, 7
add ebx, [rsp+8*4+((1024+15-(14)) MOD (16))*4]
xor ebp, edi
add edx, [rsi+(14)*4]
ror edi, 11
add edx, [rsp+((1024+7-(14)) MOD (8))*4]
xor ebp, edi
add ebp, ebx
mov [rsp+8*4+((1024+15-(14)) MOD (16))*4], ebp
add edx, ebp
mov ebx, ecx
xor ecx, [rsp+((1024+7-(14+6)) MOD (8))*4]
and eax, ecx
xor eax, [rsp+((1024+7-(14+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add eax, edx
add edx, [rsp+((1024+7-(14+4)) MOD (8))*4]
mov [rsp+((1024+7-(14+4)) MOD (8))*4], edx
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add eax, ebp
mov [rsp+((1024+7-(14)) MOD (8))*4], eax
mov edi, [rsp+((1024+7-(15+2)) MOD (8))*4]
xor edi, [rsp+((1024+7-(15+1)) MOD (8))*4]
and edi, edx
xor edi, [rsp+((1024+7-(15+1)) MOD (8))*4]
mov ebp, edx
ror edx, 6
ror ebp, 25
xor ebp, edx
ror edx, 5
xor ebp, edx
add edi, ebp
mov ebp, [rsp+8*4+((1024+15-((15)-2)) MOD (16))*4]
mov edx, [rsp+8*4+((1024+15-((15)-15)) MOD (16))*4]
mov ebx, ebp
shr ebp, 10
ror ebx, 17
xor ebp, ebx
ror ebx, 2
xor ebx, ebp
add ebx, [rsp+8*4+((1024+15-((15)-7)) MOD (16))*4]
mov ebp, edx
shr ebp, 3
ror edx, 7
add ebx, [rsp+8*4+((1024+15-(15)) MOD (16))*4]
xor ebp, edx
add edi, [rsi+(15)*4]
ror edx, 11
add edi, [rsp+((1024+7-(15)) MOD (8))*4]
xor ebp, edx
add ebp, ebx
mov [rsp+8*4+((1024+15-(15)) MOD (16))*4], ebp
add edi, ebp
mov ebx, eax
xor eax, [rsp+((1024+7-(15+6)) MOD (8))*4]
and ecx, eax
xor ecx, [rsp+((1024+7-(15+6)) MOD (8))*4]
mov ebp, ebx
ror ebx, 2
add ecx, edi
add edi, [rsp+((1024+7-(15+4)) MOD (8))*4]
mov [rsp+((1024+7-(15+4)) MOD (8))*4], edi
ror ebp, 22
xor ebp, ebx
ror ebx, 11
xor ebp, ebx
add ecx, ebp
mov [rsp+((1024+7-(15)) MOD (8))*4], ecx
cmp rsi, [rsp+8*4+16*4+0*8]
jne label1
mov rcx, [rsp+8*4+16*4+1*8]
movdqa xmm1, XMMWORD PTR [rcx+1*16]
movdqa xmm0, XMMWORD PTR [rcx+0*16]
paddd xmm1, [rsp+((1024+7-(0+3)) MOD (8))*4]
paddd xmm0, [rsp+((1024+7-(0+7)) MOD (8))*4]
movdqa [rcx+1*16], xmm1
movdqa [rcx+0*16], xmm0
mov rdx, [rsp+8*4+16*4+2*8]
add rdx, 64
mov [rsp+8*4+16*4+2*8], rdx
cmp rdx, [rsp+8*4+16*4+3*8]
jne label0
add		rsp, 8*4 + 16*4 + 4*8 + 8
pop		rbp
pop		rbx
pop		rdi
pop		rsi
ret
X86_SHA256_HashBlocks ENDP

_TEXT ENDS
END
