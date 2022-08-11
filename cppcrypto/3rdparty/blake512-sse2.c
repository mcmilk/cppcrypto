// BLAKE-512 sse2 eBASH implementation
// authors:   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
//      Shawn Kirst <skirst@gmail.com>
//      Samuel Neves <sneves@dei.uc.pt>
//      Peter Schwabe <peter@cryptojedi.org>
//
// This implementation assumes that no salt is used.
//
// Level of copyright protection: 0
// Level of patent protection: 0
//

// Modified by kerukuro for use in cppcrypto.

#include <string.h>
#include <stdio.h>
#include <emmintrin.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifndef _M_X64
__inline __m128i i64tom128i(int64_t i0, int64_t i1) {
#if defined (_MSC_VER) && ! defined(__INTEL_COMPILER)
	// MS compiler has no _mm_set_epi64x in 32 bit mode
#if defined(_M_X64)                                    // 64 bit mode
#if _MSC_VER < 1700
	__m128i x0 = _mm_cvtsi64_si128(i0);                // 64 bit load
	__m128i x1 = _mm_cvtsi64_si128(i1);                // 64 bit load
	return _mm_unpacklo_epi64(x0, x1);                   // combine
#else
	return _mm_set_epi64x(i1, i0);
#endif
#else   // MS compiler in 32-bit mode
#if _MSC_VER < 1900
	union {
		int64_t q[2];
		int32_t r[4];
	} u;
	u.q[0] = i1;  u.q[1] = i0;
	// this is inefficient, but other solutions are worse
	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
#else
	return _mm_set_epi64x(i1, i0);
#endif
#endif  // __x86_64__
#else   // Other compilers
	return _mm_set_epi64x(i1, i0);
#endif
};
#else 
#define i64tom128i(a,b) _mm_set_epi64x(a,b)
#endif

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

#define _mm_set_pi64x(a) a


#define LOADU(p)  _mm_loadu_si128( (__m128i *)(p) )
#define BSWAP64(r) do { \
   r = _mm_shuffle_epi32(r, _MM_SHUFFLE(2, 3, 0, 1)); \
   r = _mm_shufflehi_epi16(r, _MM_SHUFFLE(2, 3, 0, 1)); \
   r = _mm_shufflelo_epi16(r, _MM_SHUFFLE(2, 3, 0, 1)); \
   r = _mm_xor_si128(_mm_slli_epi16(r, 8), _mm_srli_epi16(r, 8)); \
} while(0)



int blake512_compress_sse2(u64* h, u64 t0, int padding, const u8 * datablock)
{

	__m128i row1a, row1b;
	__m128i row2a, row2b;
	__m128i row3a, row3b;
	__m128i row4a, row4b;
	__m128i buf1a, buf2a;

	u64 t1 = 0ULL;

	union {
		u64     u64[16];
		__m128i u128[8];
	} m;
	u64 y[16];

	/* constants and permutation */
	static const int sig[][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
	};

	static const u64 z[16] = {
		0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL,
		0xA4093822299F31D0ULL, 0x082EFA98EC4E6C89ULL,
		0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL,
		0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL,
		0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL,
		0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL,
		0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL,
		0x0801F2E2858EFC16ULL, 0x636920D871574E69ULL
	};



	/* get message */
	m.u128[0] = LOADU(datablock + 0);
	m.u128[1] = LOADU(datablock + 16);
	m.u128[2] = LOADU(datablock + 32);
	m.u128[3] = LOADU(datablock + 48);
	m.u128[4] = LOADU(datablock + 64);
	m.u128[5] = LOADU(datablock + 80);
	m.u128[6] = LOADU(datablock + 96);
	m.u128[7] = LOADU(datablock + 112);

	BSWAP64(m.u128[0]);
	BSWAP64(m.u128[1]);
	BSWAP64(m.u128[2]);
	BSWAP64(m.u128[3]);
	BSWAP64(m.u128[4]);
	BSWAP64(m.u128[5]);
	BSWAP64(m.u128[6]);
	BSWAP64(m.u128[7]);

	row1b = i64tom128i(h[3], h[2]);
	row1a = i64tom128i(h[1], h[0]);
	row2b = i64tom128i(h[7], h[6]);
	row2a = i64tom128i(h[5], h[4]);
	row3b = i64tom128i(0x082EFA98EC4E6C89ULL, 0xA4093822299F31D0ULL);
	row3a = i64tom128i(0x13198A2E03707344ULL, 0x243F6A8885A308D3ULL);

	if (padding) {
		row4b = i64tom128i(0x3F84D5B5B5470917ULL, 0xC0AC29B7C97C50DDULL);
		row4a = i64tom128i(0xBE5466CF34E90C6CULL, 0x452821E638D01377ULL);
	}
	else {
		row4b = i64tom128i(0x3F84D5B5B5470917ULL ^ t1, 0xC0AC29B7C97C50DDULL ^ t1);
		row4a = i64tom128i(0xBE5466CF34E90C6CULL ^ t0, 0x452821E638D01377ULL ^ t0);
	}
	/* initialization ok (beware of bug on Celeron and P4!) */



#define round(r)\
    /* column step */\
    /***************************************************/\
    /* high-order side: words 0, 1, 4, 5, 8, 9, 12, 13  */		\
    buf2a = i64tom128i( m.u64[sig[r][ 2]], m.u64[sig[r][ 0]] );	\
    buf1a = i64tom128i( z[sig[r][ 3]], z[sig[r][ 1]] );	\
    buf1a = _mm_xor_si128( buf1a, buf2a );					\
    row1a = _mm_add_epi64( _mm_add_epi64(row1a, buf1a), row2a );		\
    row4a = _mm_xor_si128( row4a, row1a );				\
    row4a = _mm_shuffle_epi32(row4a, 0xB1); \
    row3a = _mm_add_epi64( row3a, row4a );				\
    row2a = _mm_xor_si128( row2a, row3a );				\
    row2a = _mm_xor_si128(_mm_srli_epi64( row2a, 25 ),_mm_slli_epi64( row2a, 39 )); \
  									\
    buf2a = i64tom128i( m.u64[sig[r][ 3]], m.u64[sig[r][ 1]] );	\
    buf1a = i64tom128i( z[sig[r][ 2]], z[sig[r][ 0]] );	\
    buf1a = _mm_xor_si128( buf1a, buf2a );					\
    row1a = _mm_add_epi64( _mm_add_epi64(row1a, buf1a), row2a );		\
    row4a = _mm_xor_si128( row4a, row1a );				\
    /*row4a = _mm_xor_si128(_mm_srli_epi64( row4a, 16 ),_mm_slli_epi64( row4a, 48 ));*/ \
    row4a = _mm_shufflelo_epi16(row4a,_MM_SHUFFLE(0,3,2,1)); \
    row4a = _mm_shufflehi_epi16(row4a,_MM_SHUFFLE(0,3,2,1)); \
    row3a = _mm_add_epi64( row3a, row4a );				\
    row2a = _mm_xor_si128( row2a, row3a );				\
    row2a = _mm_xor_si128(_mm_srli_epi64( row2a, 11 ),_mm_slli_epi64( row2a, 53 )); \
  									\
    /* same stuff for low-order side */\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][ 6]]), _mm_set_pi64x(m.u64[sig[r][ 4]] ));\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][ 7]]), _mm_set_pi64x(z[sig[r][ 5]] ));\
    buf1a = _mm_xor_si128( buf1a, buf2a );				\
    row1b = _mm_add_epi64( _mm_add_epi64(row1b, buf1a), row2b );		\
    row4b = _mm_xor_si128( row4b, row1b );				\
    row4b = _mm_shuffle_epi32(row4b, 0xB1); \
    row3b = _mm_add_epi64( row3b, row4b );				\
    row2b = _mm_xor_si128( row2b, row3b );				\
    row2b = _mm_xor_si128(_mm_srli_epi64( row2b, 25 ),_mm_slli_epi64( row2b, 39 )); \
\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][ 7]]), _mm_set_pi64x(m.u64[sig[r][ 5]] ));	\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][ 6]]), _mm_set_pi64x(z[sig[r][ 4]] ));	\
    buf1a = _mm_xor_si128( buf1a, buf2a );					\
    row1b = _mm_add_epi64( _mm_add_epi64(row1b, buf1a), row2b );		\
    row4b = _mm_xor_si128( row4b, row1b );				\
    row4b = _mm_shufflelo_epi16(row4b,_MM_SHUFFLE(0,3,2,1)); \
    row4b = _mm_shufflehi_epi16(row4b,_MM_SHUFFLE(0,3,2,1)); \
    row3b = _mm_add_epi64( row3b, row4b );				\
    row2b = _mm_xor_si128( row2b, row3b );				\
    row2b = _mm_xor_si128(_mm_srli_epi64( row2b, 11 ),_mm_slli_epi64( row2b, 53 )); \
\
    /* shuffle */\
    _mm_store_si128( 0+ (__m128i *)y, row4a); \
    _mm_store_si128( 1+ (__m128i *)y, row4b); \
    row4a = row3a;\
    row3a = row3b;\
    row3b = row4a;\
    row4a  = i64tom128i( _mm_set_pi64x(y[0]), _mm_set_pi64x(y[3] ));\
    row4b  = i64tom128i( _mm_set_pi64x(y[2]), _mm_set_pi64x(y[1] ));\
    _mm_store_si128( 0+ (__m128i *)y, row2a);  \
    _mm_store_si128( 1+ (__m128i *)y, row2b);  \
    row2a  = i64tom128i( _mm_set_pi64x(y[2]), _mm_set_pi64x(y[1] ));  \
    row2b  = i64tom128i( _mm_set_pi64x(y[0]), _mm_set_pi64x(y[3] ));  \
    /* diagonal step */\
    /***************************************************/\
    /* high-order side: words 0, 1, 4, 5, 8, 9, 12, 13  */\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][10]]), _mm_set_pi64x(m.u64[sig[r][ 8]] ));\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][11]]), _mm_set_pi64x(z[sig[r][ 9]] ));\
    buf1a = _mm_xor_si128( buf1a, buf2a );\
    row1a = _mm_add_epi64( _mm_add_epi64(row1a, buf1a), row2a );\
    row4a = _mm_xor_si128( row4a, row1a );		      \
    row4a = _mm_shuffle_epi32(row4a, 0xB1); \
    row3a = _mm_add_epi64( row3a, row4a );					\
    row2a = _mm_xor_si128( row2a, row3a );					\
    row2a = _mm_xor_si128(_mm_srli_epi64( row2a, 25 ),_mm_slli_epi64( row2a, 39 )); \
\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][11]]), _mm_set_pi64x(m.u64[sig[r][ 9]] ));\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][10]]), _mm_set_pi64x(z[sig[r][ 8]] ));\
    buf1a = _mm_xor_si128( buf1a, buf2a );\
    row1a = _mm_add_epi64( _mm_add_epi64(row1a, buf1a), row2a );\
    row4a = _mm_xor_si128( row4a, row1a );			\
    row4a = _mm_shufflelo_epi16(row4a,_MM_SHUFFLE(0,3,2,1)); \
    row4a = _mm_shufflehi_epi16(row4a,_MM_SHUFFLE(0,3,2,1)); \
    row3a = _mm_add_epi64( row3a, row4a );					\
    row2a = _mm_xor_si128( row2a, row3a );					\
    row2a = _mm_xor_si128(_mm_srli_epi64( row2a, 11 ),_mm_slli_epi64( row2a, 53 )); \
\
    /* same stuff for low-order side */\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][14]]), _mm_set_pi64x(m.u64[sig[r][12]] ));\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][15]]), _mm_set_pi64x(z[sig[r][13]] ));\
    buf1a = _mm_xor_si128( buf1a, buf2a );\
    row1b = _mm_add_epi64( _mm_add_epi64(row1b, buf1a), row2b );\
    row4b = _mm_xor_si128( row4b, row1b );			\
    buf2a = i64tom128i( _mm_set_pi64x(m.u64[sig[r][15]]), _mm_set_pi64x(m.u64[sig[r][13]] ));\
    row4b = _mm_shuffle_epi32(row4b, 0xB1); \
    row3b = _mm_add_epi64( row3b, row4b );					\
    row2b = _mm_xor_si128( row2b, row3b );					\
    buf1a = i64tom128i( _mm_set_pi64x(z[sig[r][14]]), _mm_set_pi64x(z[sig[r][12]] ));\
    row2b = _mm_xor_si128(_mm_srli_epi64( row2b, 25 ),_mm_slli_epi64( row2b, 39 )); \
\
    buf1a = _mm_xor_si128( buf1a, buf2a );\
    row1b = _mm_add_epi64( _mm_add_epi64(row1b, buf1a), row2b );\
    row4b = _mm_xor_si128( row4b, row1b );			\
    row4b = _mm_shufflelo_epi16(row4b,_MM_SHUFFLE(0,3,2,1)); \
    row4b = _mm_shufflehi_epi16(row4b,_MM_SHUFFLE(0,3,2,1)); \
    row3b = _mm_add_epi64( row3b, row4b );					\
    row2b = _mm_xor_si128( row2b, row3b );					\
    row2b = _mm_xor_si128(_mm_srli_epi64( row2b, 11 ),_mm_slli_epi64( row2b, 53 )); \
\
    /* shuffle back */\
    buf1a = row3a;\
    row3a = row3b;\
    row3b = buf1a;\
    _mm_store_si128( 0+ (__m128i *)y, row2a);	\
    _mm_store_si128( 1+ (__m128i *)y, row2b);  \
    row2a  = i64tom128i( _mm_set_pi64x(y[0]), _mm_set_pi64x(y[3] ));  \
    row2b  = i64tom128i( _mm_set_pi64x(y[2]), _mm_set_pi64x(y[1] ));  \
    _mm_store_si128( 0+ (__m128i *)y, row4a);  \
    _mm_store_si128( 1+ (__m128i *)y, row4b);  \
    row4a  = i64tom128i( _mm_set_pi64x(y[2]), _mm_set_pi64x(y[1] ));  \
    row4b  = i64tom128i( _mm_set_pi64x(y[0]), _mm_set_pi64x(y[3] ));  \
    							 \

	round(0);
	round(1);
	round(2);
	round(3);
	round(4);
	round(5);
	round(6);
	round(7);
	round(8);
	round(9);
	round(10);
	round(11);
	round(12);
	round(13);
	round(14);
	round(15);

	row1a = _mm_xor_si128(row3a, row1a);
	row1b = _mm_xor_si128(row3b, row1b);
	_mm_store_si128((__m128i *)m.u64, row1a);
	h[0] ^= m.u64[0];
	h[1] ^= m.u64[1];
	_mm_store_si128((__m128i *)m.u64, row1b);
	h[2] ^= m.u64[0];
	h[3] ^= m.u64[1];

	row2a = _mm_xor_si128(row4a, row2a);
	row2b = _mm_xor_si128(row4b, row2b);
	_mm_store_si128((__m128i *)m.u64, row2a);
	h[4] ^= m.u64[0];
	h[5] ^= m.u64[1];
	_mm_store_si128((__m128i *)m.u64, row2b);
	h[6] ^= m.u64[0];
	h[7] ^= m.u64[1];

	return 0;
}
