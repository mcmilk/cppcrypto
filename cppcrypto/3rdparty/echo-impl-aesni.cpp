/*
#------------------------------------------------------------------------------------ #
# Implementation of the double pipe ECHO hash function in its 256-bit outputs variant.#
# Optimized for Intel AES-NI, 64-bit mode                                             #
#                                                                                     #
# Date:     2010-07-23                                                                #
#                                                                                     #
# Authors:  Ryad Benadjila  <ryadbenadjila@gmail.com>                                 #
#           Olivier Billet  <billet@eurecom.fr>                                       #
#------------------------------------------------------------------------------------ #
//
// Translated to C++ intrinsics by kerukuro for use in cppcrypto.
// Modified by kerukuro for use in cppcrypto.
//
*/

#include <wmmintrin.h>
#include <tmmintrin.h>
#include "../echo-impl.h"

namespace cppcrypto {
	namespace detail {

		static void do_init(uint64_t* h, uint64_t* salt, int r, unsigned long long* MEM_CST, unsigned char* SHA3_FULL_CNT)
		{
			MEM_CST[0] = 0x0000000000000000ULL;
			MEM_CST[1] = 0x0000000000000000ULL;
			MEM_CST[2] = 0x8080808080808080ULL;
			MEM_CST[3] = 0x8080808080808080ULL;
			MEM_CST[4] = 0x001b001b001b001bULL;
			MEM_CST[5] = 0x001b001b001b001bULL;
			MEM_CST[6] = 0x0101010101010101ULL;
			MEM_CST[7] = 0x0101010101010101ULL;
			MEM_CST[8] = 0xfefefefefefefefeULL;
			MEM_CST[9] = 0xfefefefefefefefeULL;

			memcpy(&MEM_CST[10], salt, 16);

			memset(SHA3_FULL_CNT, 0, r * 16 * 16);
			//for (int i = 0; i < r * 16; i++)
				//((unsigned long long*) & (SHA3_FULL_CNT[r * 16 - i - 1]))[1] = 0;
		}

		static void do_transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal, int r, unsigned char* OLDCV, unsigned char* MEM_CST, unsigned char* SHA3_FULL_CNT)
		{
            __m128i* const chaining = (__m128i*) h;
            __m128i xmm0 = chaining[0];
            __m128i xmm1 = chaining[1];
            __m128i xmm2 = chaining[2];
            __m128i xmm3 = chaining[3];
            __m128i xmm4 = chaining[4];
            __m128i xmm5 = chaining[5];
            __m128i xmm6 = chaining[6];
            __m128i xmm7 = chaining[7];
            __m128i xmm8 = chaining[8];
            __m128i xmm9 = chaining[9];
            __m128i xmm10 = chaining[10];
            __m128i xmm11 = chaining[11];
            __m128i xmm12 = chaining[12];
            __m128i xmm13 = chaining[13];
            __m128i xmm14 = chaining[14];
            __m128i xmm15 = chaining[15];

            __m128i* oldcv = (__m128i*) OLDCV;

            if (r <= 8)
            {
                xmm0 = _mm_xor_si128(xmm0, xmm4);
                xmm1 = _mm_xor_si128(xmm1, xmm5);
                xmm2 = _mm_xor_si128(xmm2, xmm6);
                xmm3 = _mm_xor_si128(xmm3, xmm7);
                xmm0 = _mm_xor_si128(xmm0, xmm8);
                xmm1 = _mm_xor_si128(xmm1, xmm9);
                xmm2 = _mm_xor_si128(xmm2, xmm10);
                xmm3 = _mm_xor_si128(xmm3, xmm11);
                xmm0 = _mm_xor_si128(xmm0, xmm12);
                xmm1 = _mm_xor_si128(xmm1, xmm13);
                xmm2 = _mm_xor_si128(xmm2, xmm14);
                xmm3 = _mm_xor_si128(xmm3, xmm15);
                oldcv[0] = xmm0;
                oldcv[1] = xmm1;
                oldcv[2] = xmm2;
                oldcv[3] = xmm3;
                xmm0 = chaining[0];
                xmm1 = chaining[1];
                xmm2 = chaining[2];
                xmm3 = chaining[3];
            }
            else
            {
                xmm0 = _mm_xor_si128(xmm0, xmm8);
                xmm1 = _mm_xor_si128(xmm1, xmm9);
                xmm2 = _mm_xor_si128(xmm2, xmm10);
                xmm3 = _mm_xor_si128(xmm3, xmm11);
                xmm4 = _mm_xor_si128(xmm4, xmm12);
                xmm5 = _mm_xor_si128(xmm5, xmm13);
                xmm6 = _mm_xor_si128(xmm6, xmm14);
                xmm7 = _mm_xor_si128(xmm7, xmm15);
                oldcv[0] = xmm0;
                oldcv[1] = xmm1;
                oldcv[2] = xmm2;
                oldcv[3] = xmm3;
                oldcv[4] = xmm4;
                oldcv[5] = xmm5;
                oldcv[6] = xmm6;
                oldcv[7] = xmm7;
                xmm0 = chaining[0];
                xmm1 = chaining[1];
                xmm2 = chaining[2];
                xmm3 = chaining[3];
                xmm4 = chaining[4];
                xmm5 = chaining[5];
                xmm6 = chaining[6];
                xmm7 = chaining[7];
            }
            uint64_t rdx = 0;
            if (addedbits)
                rdx = total + addtototal;
            uint64_t rax = rdx;
            uint64_t rbx = rdx;
            uint64_t rcx = rdx;
            uint64_t rsi = r * 16 * 2;
            rbx += 1;
            rcx += 2;
            rdx += 3;
            __m128i* const sha3fullcnt = (__m128i*) SHA3_FULL_CNT;
            uint64_t* sha3fullcnt64 = (uint64_t*)SHA3_FULL_CNT;
            while (rsi)
            {
                sha3fullcnt64[rsi - 1 * 2] = rax;
                sha3fullcnt64[rsi - 2 * 2] = rbx;
                rax += 4;
                rbx += 4;
                sha3fullcnt64[rsi - 3 * 2] = rcx;
                sha3fullcnt64[rsi - 4 * 2] = rdx;
                rcx += 4;
                rdx += 4;
                sha3fullcnt64[rsi - 5 * 2] = rax;
                sha3fullcnt64[rsi - 6 * 2] = rbx;
                rax += 4;
                rbx += 4;
                sha3fullcnt64[rsi - 7 * 2] = rcx;
                sha3fullcnt64[rsi - 8 * 2] = rdx;
                rcx += 4;
                rdx += 4;
                sha3fullcnt64[rsi - 9 * 2] = rax;
                sha3fullcnt64[rsi - 10 * 2] = rbx;
                rax += 4;
                rbx += 4;
                sha3fullcnt64[rsi - 11 * 2] = rcx;
                sha3fullcnt64[rsi - 12 * 2] = rdx;
                rcx += 4;
                rdx += 4;
                sha3fullcnt64[rsi - 13 * 2] = rax;
                sha3fullcnt64[rsi - 14 * 2] = rbx;
                rax += 4;
                rbx += 4;
                sha3fullcnt64[rsi - 15 * 2] = rcx;
                sha3fullcnt64[rsi - 16 * 2] = rdx;
                rcx += 4;
                rdx += 4;
                rsi -= 16 * 2;
            }

            rcx = r * 16;
            __m128i* const memcst = (__m128i*) MEM_CST;
            while (rcx)
            {
                xmm0 = _mm_aesenc_si128(xmm0, sha3fullcnt[rcx - 1]);
                xmm1 = _mm_aesenc_si128(xmm1, sha3fullcnt[rcx - 2]);
                xmm2 = _mm_aesenc_si128(xmm2, sha3fullcnt[rcx - 3]);
                xmm3 = _mm_aesenc_si128(xmm3, sha3fullcnt[rcx - 4]);
                xmm4 = _mm_aesenc_si128(xmm4, sha3fullcnt[rcx - 5]);
                xmm5 = _mm_aesenc_si128(xmm5, sha3fullcnt[rcx - 6]);
                xmm6 = _mm_aesenc_si128(xmm6, sha3fullcnt[rcx - 7]);
                xmm7 = _mm_aesenc_si128(xmm7, sha3fullcnt[rcx - 8]);
                xmm8 = _mm_aesenc_si128(xmm8, sha3fullcnt[rcx - 9]);
                xmm9 = _mm_aesenc_si128(xmm9, sha3fullcnt[rcx - 10]);
                xmm10 = _mm_aesenc_si128(xmm10, sha3fullcnt[rcx - 11]);
                xmm11 = _mm_aesenc_si128(xmm11, sha3fullcnt[rcx - 12]);
                xmm12 = _mm_aesenc_si128(xmm12, sha3fullcnt[rcx - 13]);
                xmm13 = _mm_aesenc_si128(xmm13, sha3fullcnt[rcx - 14]);
                xmm14 = _mm_aesenc_si128(xmm14, sha3fullcnt[rcx - 15]);
                xmm15 = _mm_aesenc_si128(xmm15, sha3fullcnt[rcx - 16]);


                xmm0 = _mm_aesenc_si128(xmm0, memcst[5]);
                xmm1 = _mm_aesenc_si128(xmm1, memcst[5]);
                xmm2 = _mm_aesenc_si128(xmm2, memcst[5]);
                xmm3 = _mm_aesenc_si128(xmm3, memcst[5]);
                xmm4 = _mm_aesenc_si128(xmm4, memcst[5]);
                xmm5 = _mm_aesenc_si128(xmm5, memcst[5]);
                xmm6 = _mm_aesenc_si128(xmm6, memcst[5]);
                xmm7 = _mm_aesenc_si128(xmm7, memcst[5]);
                xmm8 = _mm_aesenc_si128(xmm8, memcst[5]);
                xmm9 = _mm_aesenc_si128(xmm9, memcst[5]);
                xmm10 = _mm_aesenc_si128(xmm10, memcst[5]);
                xmm11 = _mm_aesenc_si128(xmm11, memcst[5]);
                xmm12 = _mm_aesenc_si128(xmm12, memcst[5]);
                xmm13 = _mm_aesenc_si128(xmm13, memcst[5]);
                xmm14 = _mm_aesenc_si128(xmm14, memcst[5]);
                xmm15 = _mm_aesenc_si128(xmm15, memcst[5]);

                chaining[11] = xmm11;
                chaining[10] = xmm6;
                chaining[9] = xmm1;
                chaining[8] = xmm12;
                chaining[7] = xmm7;
                chaining[6] = xmm2;
                chaining[5] = xmm13;
                chaining[4] = xmm8;
                chaining[3] = xmm3;
                chaining[2] = xmm14;
                chaining[1] = xmm9;
                chaining[0] = xmm4;




                xmm13 = memcst[2];
                xmm14 = memcst[1];
                xmm7 = xmm0;
                xmm1 = xmm5;
                xmm2 = xmm10;
                xmm3 = xmm15;

                xmm4 = _mm_xor_si128(xmm4, xmm4);
                xmm0 = _mm_xor_si128(xmm0, xmm1);
                xmm2 = _mm_xor_si128(xmm2, xmm3);
                xmm1 = xmm0;
                xmm4 = _mm_xor_si128(xmm4, xmm14);
                xmm3 = _mm_xor_si128(xmm3, xmm7);
                xmm1 = _mm_xor_si128(xmm1, xmm2);

                xmm4 = _mm_and_si128(xmm4, xmm0);
                xmm0 = _mm_xor_si128(xmm0, xmm4);
                xmm6 = _mm_xor_si128(xmm6, xmm6);
                xmm4 = _mm_srli_epi16(xmm4, 7);
                xmm0 = _mm_slli_epi16(xmm0, 1);
                xmm4 = _mm_mullo_epi16(xmm4, xmm13);
                xmm6 = _mm_xor_si128(xmm6, xmm14);
                xmm0 = _mm_xor_si128(xmm0, xmm4);

                xmm6 = _mm_and_si128(xmm6, xmm2);
                xmm2 = _mm_xor_si128(xmm2, xmm6);
                xmm4 = _mm_xor_si128(xmm4, xmm4);
                xmm6 = _mm_srli_epi16(xmm6, 7);
                xmm2 = _mm_slli_epi16(xmm2, 1);
                xmm6 = _mm_mullo_epi16(xmm6, xmm13);
                xmm4 = _mm_xor_si128(xmm4, xmm14);
                xmm2 = _mm_xor_si128(xmm2, xmm6);

                xmm4 = _mm_and_si128(xmm4, xmm3);
                xmm3 = _mm_xor_si128(xmm3, xmm4);
                xmm4 = _mm_srli_epi16(xmm4, 7);
                xmm3 = _mm_slli_epi16(xmm3, 1);
                xmm4 = _mm_mullo_epi16(xmm4, xmm13);
                xmm3 = _mm_xor_si128(xmm3, xmm4);

                xmm4 = xmm2;
                xmm0 = _mm_xor_si128(xmm0, xmm1);
                xmm4 = _mm_xor_si128(xmm4, xmm3);
                xmm2 = _mm_xor_si128(xmm2, xmm1);
                xmm4 = _mm_xor_si128(xmm4, xmm0);
                xmm3 = _mm_xor_si128(xmm3, xmm1);
                xmm1 = xmm4;
                xmm0 = _mm_xor_si128(xmm0, xmm7);
                xmm2 = _mm_xor_si128(xmm2, xmm10);
                xmm3 = _mm_xor_si128(xmm3, xmm15);
                xmm1 = _mm_xor_si128(xmm1, xmm5);

                xmm4 = chaining[0];
                xmm5 = chaining[1];
                xmm6 = chaining[2];
                xmm7 = chaining[3];

                xmm8 = _mm_xor_si128(xmm8, xmm8);
                xmm4 = _mm_xor_si128(xmm4, xmm5);
                xmm6 = _mm_xor_si128(xmm6, xmm7);
                xmm5 = xmm4;
                xmm8 = _mm_xor_si128(xmm8, xmm14);
                xmm7 = _mm_xor_si128(xmm7, chaining[0]);
                xmm5 = _mm_xor_si128(xmm5, xmm6);

                xmm8 = _mm_and_si128(xmm8, xmm4);
                xmm4 = _mm_xor_si128(xmm4, xmm8);
                xmm9 = _mm_xor_si128(xmm9, xmm9);
                xmm8 = _mm_srli_epi16(xmm8, 7);
                xmm4 = _mm_slli_epi16(xmm4, 1);
                xmm8 = _mm_mullo_epi16(xmm8, xmm13);
                xmm9 = _mm_xor_si128(xmm9, xmm14);
                xmm4 = _mm_xor_si128(xmm4, xmm8);

                xmm9 = _mm_and_si128(xmm9, xmm6);
                xmm6 = _mm_xor_si128(xmm6, xmm9);
                xmm8 = _mm_xor_si128(xmm8, xmm8);
                xmm9 = _mm_srli_epi16(xmm9, 7);
                xmm6 = _mm_slli_epi16(xmm6, 1);
                xmm9 = _mm_mullo_epi16(xmm9, xmm13);
                xmm8 = _mm_xor_si128(xmm8, xmm14);
                xmm6 = _mm_xor_si128(xmm6, xmm9);

                xmm8 = _mm_and_si128(xmm8, xmm7);
                xmm7 = _mm_xor_si128(xmm7, xmm8);
                xmm8 = _mm_srli_epi16(xmm8, 7);
                xmm7 = _mm_slli_epi16(xmm7, 1);
                xmm8 = _mm_mullo_epi16(xmm8, xmm13);
                xmm7 = _mm_xor_si128(xmm7, xmm8);

                xmm8 = xmm6;
                xmm4 = _mm_xor_si128(xmm4, xmm5);
                xmm8 = _mm_xor_si128(xmm8, xmm7);
                xmm6 = _mm_xor_si128(xmm6, xmm5);
                xmm8 = _mm_xor_si128(xmm8, xmm4);
                xmm7 = _mm_xor_si128(xmm7, xmm5);
                xmm5 = xmm8;

                xmm8 = chaining[4];
                xmm9 = chaining[5];
                xmm10 = chaining[6];
                xmm11 = chaining[7];
                xmm4 = _mm_xor_si128(xmm4, chaining[0]);
                xmm5 = _mm_xor_si128(xmm5, chaining[1]);
                xmm6 = _mm_xor_si128(xmm6, chaining[2]);
                xmm7 = _mm_xor_si128(xmm7, chaining[3]);

                xmm12 = _mm_xor_si128(xmm12, xmm12);
                xmm8 = _mm_xor_si128(xmm8, xmm9);
                xmm10 = _mm_xor_si128(xmm10, xmm11);
                xmm9 = xmm8;
                xmm12 = _mm_xor_si128(xmm12, xmm14);
                xmm11 = _mm_xor_si128(xmm11, chaining[4]);
                xmm9 = _mm_xor_si128(xmm9, xmm10);

                xmm12 = _mm_and_si128(xmm12, xmm8);
                xmm8 = _mm_xor_si128(xmm8, xmm12);
                xmm15 = _mm_xor_si128(xmm15, xmm15);
                xmm12 = _mm_srli_epi16(xmm12, 7);
                xmm8 = _mm_slli_epi16(xmm8, 1);
                xmm12 = _mm_mullo_epi16(xmm12, xmm13);
                xmm15 = _mm_xor_si128(xmm15, xmm14);
                xmm8 = _mm_xor_si128(xmm8, xmm12);

                xmm15 = _mm_and_si128(xmm15, xmm10);
                xmm10 = _mm_xor_si128(xmm10, xmm15);
                xmm12 = _mm_xor_si128(xmm12, xmm12);
                xmm15 = _mm_srli_epi16(xmm15, 7);
                xmm10 = _mm_slli_epi16(xmm10, 1);
                xmm15 = _mm_mullo_epi16(xmm15, xmm13);
                xmm12 = _mm_xor_si128(xmm12, xmm14);
                xmm10 = _mm_xor_si128(xmm10, xmm15);

                xmm12 = _mm_and_si128(xmm12, xmm11);
                xmm11 = _mm_xor_si128(xmm11, xmm12);
                xmm12 = _mm_srli_epi16(xmm12, 7);
                xmm11 = _mm_slli_epi16(xmm11, 1);
                xmm12 = _mm_mullo_epi16(xmm12, xmm13);
                xmm11 = _mm_xor_si128(xmm11, xmm12);

                xmm12 = xmm10;
                xmm8 = _mm_xor_si128(xmm8, xmm9);
                xmm12 = _mm_xor_si128(xmm12, xmm11);
                xmm10 = _mm_xor_si128(xmm10, xmm9);
                xmm12 = _mm_xor_si128(xmm12, xmm8);
                xmm11 = _mm_xor_si128(xmm11, xmm9);
                xmm9 = xmm12;

                xmm12 = chaining[8];
                xmm13 = chaining[9];
                xmm14 = chaining[10];
                xmm15 = chaining[11];
                chaining[12] = xmm0;
                xmm8 = _mm_xor_si128(xmm8, chaining[4]);
                xmm9 = _mm_xor_si128(xmm9, chaining[5]);
                xmm10 = _mm_xor_si128(xmm10, chaining[6]);
                xmm11 = _mm_xor_si128(xmm11, chaining[7]);


                xmm0 = _mm_xor_si128(xmm0, xmm0);
                xmm12 = _mm_xor_si128(xmm12, xmm13);
                xmm14 = _mm_xor_si128(xmm14, xmm15);
                xmm13 = xmm12;
                xmm0 = _mm_xor_si128(xmm0, memcst[1]);
                xmm15 = _mm_xor_si128(xmm15, chaining[8]);
                xmm13 = _mm_xor_si128(xmm13, xmm14);


                xmm0 = _mm_and_si128(xmm0, xmm12);
                xmm12 = _mm_xor_si128(xmm12, xmm0);
                xmm0 = _mm_srli_epi16(xmm0, 7);
                xmm12 = _mm_slli_epi16(xmm12, 1);
                xmm0 = _mm_mullo_epi16(xmm0, memcst[2]);
                xmm12 = _mm_xor_si128(xmm12, xmm0);




                xmm0 = memcst[1];
                xmm0 = _mm_and_si128(xmm0, xmm14);
                xmm14 = _mm_xor_si128(xmm14, xmm0);
                xmm0 = _mm_srli_epi16(xmm0, 7);
                xmm14 = _mm_slli_epi16(xmm14, 1);
                xmm0 = _mm_mullo_epi16(xmm0, memcst[2]);
                xmm14 = _mm_xor_si128(xmm14, xmm0);

                xmm0 = memcst[1];
                xmm0 = _mm_and_si128(xmm0, xmm15);
                xmm15 = _mm_xor_si128(xmm15, xmm0);
                xmm0 = _mm_srli_epi16(xmm0, 7);
                xmm15 = _mm_slli_epi16(xmm15, 1);
                xmm0 = _mm_mullo_epi16(xmm0, memcst[2]);
                xmm15 = _mm_xor_si128(xmm15, xmm0);

                xmm0 = xmm14;
                xmm12 = _mm_xor_si128(xmm12, xmm13);
                xmm0 = _mm_xor_si128(xmm0, xmm15);
                xmm14 = _mm_xor_si128(xmm14, xmm13);
                xmm0 = _mm_xor_si128(xmm0, xmm12);
                xmm15 = _mm_xor_si128(xmm15, xmm13);
                xmm13 = xmm0;
                xmm12 = _mm_xor_si128(xmm12, chaining[8]);
                xmm13 = _mm_xor_si128(xmm13, chaining[9]);
                xmm14 = _mm_xor_si128(xmm14, chaining[10]);
                xmm15 = _mm_xor_si128(xmm15, chaining[11]);
                xmm0 = chaining[12];

                rcx -= 16;


            }

            if (r <= 8)
            {
                xmm0 = _mm_xor_si128(xmm0, xmm4);
                xmm1 = _mm_xor_si128(xmm1, xmm5);
                xmm2 = _mm_xor_si128(xmm2, xmm6);
                xmm3 = _mm_xor_si128(xmm3, xmm7);

                xmm0 = _mm_xor_si128(xmm0, xmm8);
                xmm1 = _mm_xor_si128(xmm1, xmm9);
                xmm2 = _mm_xor_si128(xmm2, xmm10);
                xmm3 = _mm_xor_si128(xmm3, xmm11);

                xmm0 = _mm_xor_si128(xmm0, xmm12);
                xmm1 = _mm_xor_si128(xmm1, xmm13);
                xmm2 = _mm_xor_si128(xmm2, xmm14);
                xmm3 = _mm_xor_si128(xmm3, xmm15);

                xmm0 = _mm_xor_si128(xmm0, oldcv[0]);
                xmm1 = _mm_xor_si128(xmm1, oldcv[1]);
                xmm2 = _mm_xor_si128(xmm2, oldcv[2]);
                xmm3 = _mm_xor_si128(xmm3, oldcv[3]);

                chaining[0] = xmm0;
                chaining[1] = xmm1;
                chaining[2] = xmm2;
                chaining[3] = xmm3;
            }
            else
            {
                xmm0 = _mm_xor_si128(xmm0, xmm8);
                xmm1 = _mm_xor_si128(xmm1, xmm9);
                xmm2 = _mm_xor_si128(xmm2, xmm10);
                xmm3 = _mm_xor_si128(xmm3, xmm11);

                xmm4 = _mm_xor_si128(xmm4, xmm12);
                xmm5 = _mm_xor_si128(xmm5, xmm13);
                xmm6 = _mm_xor_si128(xmm6, xmm14);
                xmm7 = _mm_xor_si128(xmm7, xmm15);

                xmm0 = _mm_xor_si128(xmm0, oldcv[0]);
                xmm1 = _mm_xor_si128(xmm1, oldcv[1]);
                xmm2 = _mm_xor_si128(xmm2, oldcv[2]);
                xmm3 = _mm_xor_si128(xmm3, oldcv[3]);
                xmm4 = _mm_xor_si128(xmm4, oldcv[4]);
                xmm5 = _mm_xor_si128(xmm5, oldcv[5]);
                xmm6 = _mm_xor_si128(xmm6, oldcv[6]);
                xmm7 = _mm_xor_si128(xmm7, oldcv[7]);

                chaining[0] = xmm0;
                chaining[1] = xmm1;
                chaining[2] = xmm2;
                chaining[3] = xmm3;
                chaining[4] = xmm4;
                chaining[5] = xmm5;
                chaining[6] = xmm6;
                chaining[7] = xmm7;
            }
		}

		void echo_impl_aesni_256::init(uint64_t* h, uint64_t* salt)
		{
			do_init(h, salt, 8, reinterpret_cast<unsigned long long*>(MEM_CST.get()), SHA3_FULL_CNT.get());
		}

		void echo_impl_aesni_512::init(uint64_t* h, uint64_t* salt)
		{
			do_init(h, salt, 10, reinterpret_cast<unsigned long long*>(MEM_CST.get()), SHA3_FULL_CNT.get());
		}

        void echo_impl_aesni_256::transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal)
        {
            do_transform(h, salt, total, addedbits, addtototal, 8, OLDCV, MEM_CST, SHA3_FULL_CNT);
        }

        void echo_impl_aesni_512::transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal)
        {
            do_transform(h, salt, total, addedbits, addtototal, 10, OLDCV, MEM_CST, SHA3_FULL_CNT);
        }

	} // namespace detail
} // namespace cppcrypto
