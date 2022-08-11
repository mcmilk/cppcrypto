// BLAKE-512 sse41 eBASH implementation
// Authors: Jean-Philippe Aumasson and Samuel Neves.

// Modified by kerukuro for use in cppcrypto.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <emmintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#define AVOID_BRANCHING 1
#include "blake512-sse41-rounds.h"

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;


#ifndef _M_X64
#ifdef _MSC_VER
#if _MSC_VER < 1900
__inline __m128i _mm_set_epi64x(int64_t i0, int64_t i1) {
	union {
		int64_t q[2];
		int32_t r[4];
	} u;
	u.q[0] = i1;  u.q[1] = i0;
	// this is inefficient, but other solutions are worse
	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
}
#pragma warning(disable:4799)
__inline __m128i _mm_set1_epi64x(int64_t a)
{
	union {
		__m64 m;
		long long ii;
	} u;
	u.ii = a;
	return _mm_set1_epi64(u.m);
}
#pragma warning(default:4799)
#endif
#endif
#endif


int blake512_compress_sse41(u64* h, u64 total, int padding, const u8 * datablock)
{

	__m128i row1l, row1h;
	__m128i row2l, row2h;
	__m128i row3l, row3h;
	__m128i row4l, row4h;

	const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	const __m128i u8to64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);

	__m128i m0, m1, m2, m3, m4, m5, m6, m7;
	__m128i t0, t1, t2, t3;
	__m128i b0, b1;

	m0 = _mm_loadu_si128((__m128i*)(datablock + 0));
	m1 = _mm_loadu_si128((__m128i*)(datablock + 16));
	m2 = _mm_loadu_si128((__m128i*)(datablock + 32));
	m3 = _mm_loadu_si128((__m128i*)(datablock + 48));
	m4 = _mm_loadu_si128((__m128i*)(datablock + 64));
	m5 = _mm_loadu_si128((__m128i*)(datablock + 80));
	m6 = _mm_loadu_si128((__m128i*)(datablock + 96));
	m7 = _mm_loadu_si128((__m128i*)(datablock + 112));

	m0 = BSWAP64(m0);
	m1 = BSWAP64(m1);
	m2 = BSWAP64(m2);
	m3 = BSWAP64(m3);
	m4 = BSWAP64(m4);
	m5 = BSWAP64(m5);
	m6 = BSWAP64(m6);
	m7 = BSWAP64(m7);

	row1h = _mm_set_epi64x(h[3], h[2]);
	row1l = _mm_set_epi64x(h[1], h[0]);
	row2h = _mm_set_epi64x(h[7], h[6]);
	row2l = _mm_set_epi64x(h[5], h[4]);

	row3l = _mm_set_epi64x(0x13198A2E03707344ULL, 0x243F6A8885A308D3ULL);
	row3h = _mm_set_epi64x(0x082EFA98EC4E6C89ULL, 0xA4093822299F31D0ULL);

	row4l = _mm_set_epi64x(0xBE5466CF34E90C6CULL, 0x452821E638D01377ULL);
	row4h = _mm_set_epi64x(0x3F84D5B5B5470917ULL, 0xC0AC29B7C97C50DDULL);

#ifdef AVOID_BRANCHING
	do
	{
		const __m128i mask = _mm_cmpeq_epi32(_mm_setzero_si128(), _mm_set1_epi32(padding));
		const __m128i xor1 = _mm_and_si128(_mm_set1_epi64x(total), mask);
		const __m128i xor2 = _mm_and_si128(_mm_set1_epi64x(0ULL), mask);
		row4l = _mm_xor_si128(row4l, xor1);
		row4h = _mm_xor_si128(row4h, xor2);
	} while (0);
#else
	if (!state->nullt)
	{
		row4l = _mm_xor_si128(row4l, _mm_set1_epi64x(total));
		row4h = _mm_xor_si128(row4h, _mm_set1_epi64x(0ULL));
	}
#endif

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);
	ROUND(12);
	ROUND(13);
	ROUND(14);
	ROUND(15);

#ifndef _M_X64
	_mm_empty();
#endif

	row1l = _mm_xor_si128(row3l, row1l);
	row1h = _mm_xor_si128(row3h, row1h);

#ifdef _MSC_VER
	h[0] ^= row1l.m128i_u64[0];
	h[1] ^= row1l.m128i_u64[1];
	h[2] ^= row1h.m128i_u64[0];
	h[3] ^= row1h.m128i_u64[1];
#else
        const int64_t *r1l64 = (const int64_t*) &row1l;
        const int64_t *r1h64 = (const int64_t*) &row1h;
	h[0] ^= r1l64[0];
	h[1] ^= r1l64[1];
	h[2] ^= r1h64[0];
	h[3] ^= r1h64[1];
#endif

	row2l = _mm_xor_si128(row4l, row2l);
	row2h = _mm_xor_si128(row4h, row2h);

#ifdef _MSC_VER
	h[4] ^= row2l.m128i_u64[0];
	h[5] ^= row2l.m128i_u64[1];
	h[6] ^= row2h.m128i_u64[0];
	h[7] ^= row2h.m128i_u64[1];
#else
        const int64_t *r2l64 = (const int64_t*) &row2l;
        const int64_t *r2h64 = (const int64_t*) &row2h;
	h[4] ^= r2l64[0];
	h[5] ^= r2l64[1];
	h[6] ^= r2h64[0];
	h[7] ^= r2h64[1];

#endif

	return 0;
}

