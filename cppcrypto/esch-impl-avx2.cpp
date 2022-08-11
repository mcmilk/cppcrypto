/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "esch-impl.h"
#include <emmintrin.h>
#include <smmintrin.h>
#include <xmmintrin.h>
#include <immintrin.h>

#ifdef _MSC_VER
#pragma warning(disable:4752)
#endif

#if ((defined(_MSC_VER) && _MSC_VER <= 1915) || (defined(__GNUC__) && (__GNUC__ < 10 || (__GNUC__ == 10 && __GNUC_MINOR__ < 1)))) && !defined(__clang__)
static inline __m256i _mm256_zextsi128_si256(__m128i x)
{
	return _mm256_inserti128_si256(_mm256_setzero_si256(), x, 0);
}
#endif

namespace cppcrypto
{
	namespace detail
	{
		static const uint32_t C[8] = {
			0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738, 0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d
		};

		static inline __m128i hxor_epi32_avx(__m128i x)
		{
			__m128i sum64 = _mm_xor_si128(_mm_shuffle_epi32(x, 0b01001110), x);
			__m128i sum32 = _mm_xor_si128(sum64, _mm_shuffle_epi32(sum64, 0b10110001));
			return sum32;
		}

		static inline __m128i hxor3_epi32_avx(__m128i x)
		{
			__m128i t = _mm_blend_epi32(_mm_setzero_si128(), x, 0b0111);
			return hxor_epi32_avx(t);
		}

#define ROUNDCOMMON(i) \
	Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, i, C[i % 8]));\
	Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 31), _mm256_slli_epi32(Hy, 32 - 31)));\
	Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 24), _mm256_slli_epi32(Hx, 32 - 24)));\
	Hx = _mm256_xor_si256(Hx, Hc);\
	Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 17), _mm256_slli_epi32(Hy, 32 - 17)));\
	Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 17), _mm256_slli_epi32(Hx, 32 - 17)));\
	Hx = _mm256_xor_si256(Hx, Hc);\
	Hx = _mm256_add_epi32(Hx, Hy);\
	Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 31), _mm256_slli_epi32(Hx, 32 - 31)));\
	Hx = _mm256_xor_si256(Hx, Hc);\
	Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 24), _mm256_slli_epi32(Hy, 32 - 24)));\
	Hy = _mm256_xor_si256(Hy, _mm256_shuffle_epi8(Hx, r16_256));\
	Hx = _mm256_xor_si256(Hx, Hc);

#define ROUND384(i) \
	ROUNDCOMMON(i) \
	xa = hxor_epi32_avx(_mm256_castsi256_si128(Hx)); \
	ya = hxor_epi32_avx(_mm256_castsi256_si128(Hy)); \
	xa = _mm_shuffle_epi8(_mm_xor_si128(xa, _mm_slli_epi32(xa, 16)), r16_128); \
	ya = _mm_shuffle_epi8(_mm_xor_si128(ya, _mm_slli_epi32(ya, 16)), r16_128); \
	Hx = _mm256_set_m128i(_mm256_castsi256_si128(Hx), _mm_shuffle_epi32(_mm_xor_si128(ya, _mm_xor_si128(_mm256_castsi256_si128(Hx), _mm256_extracti128_si256(Hx, 1))), 0b00111001)); \
	Hy = _mm256_set_m128i(_mm256_castsi256_si128(Hy), _mm_shuffle_epi32(_mm_xor_si128(xa, _mm_xor_si128(_mm256_castsi256_si128(Hy), _mm256_extracti128_si256(Hy, 1))), 0b00111001))

#define ROUND256(i) \
	ROUNDCOMMON(i) \
	Hx = _mm256_blend_epi32(_mm256_setzero_si256(), Hx, 0b00111111);\
	Hy = _mm256_blend_epi32(_mm256_setzero_si256(), Hy, 0b00111111);\
	xa = hxor3_epi32_avx(_mm256_castsi256_si128(Hx));\
	ya = hxor3_epi32_avx(_mm256_castsi256_si128(Hy));\
	xa = _mm_shuffle_epi8(_mm_xor_si128(xa, _mm_slli_epi32(xa, 16)), r16_128);\
	ya = _mm_shuffle_epi8(_mm_xor_si128(ya, _mm_slli_epi32(ya, 16)), r16_128);\
	Hx = _mm256_blend_epi32(Hx, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hx, mask1), Hx), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(ya), mask1)), 0b00111000);\
	Hy = _mm256_blend_epi32(Hy, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hy, mask1), Hy), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(xa), mask1)), 0b00111000);\
	Hx = _mm256_permutevar8x32_epi32(Hx, mask2);\
	Hy = _mm256_permutevar8x32_epi32(Hy, mask2)


esch_avx2_impl::esch_avx2_impl()
	: r16_128(_mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
	, r16_256(_mm256_set_epi8(29, 28, 31, 30, 25, 24, 27, 26, 21, 20, 23, 22, 17, 16, 19, 18, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
{
}

esch256_avx2_impl::esch256_avx2_impl()
	: mask1(_mm256_setr_epi32(7, 7, 7, 0, 1, 2, 7, 7))
	, mask2(_mm256_set_epi32(7, 6, 2, 1, 0, 3, 5, 4))
{
}

void esch_avx2_impl::init()
{
	HHx = _mm256_setzero_si256();
	HHy = _mm256_setzero_si256();
	Hc = _mm256_loadu_si256((const __m256i*) C);
}

void esch256_avx2_impl::final(unsigned char* hash, unsigned char* m, uint64_t& total, size_t& pos)
{
	total = 1;
	if (pos < 16)
	{
		memset(&m[pos], 0, 16 - pos);
		m[pos] = 0x80;
		HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0, 0, 0, 0x1000000, 0, 0));
	}
	else
		HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0, 0, 0, 0x2000000, 0, 0));

	transform(m, 1, true);

	size_t processed = 0;
	size_t hss = 256 / 8;
	__m256i Hx = HHx;
	__m256i Hy = HHy;
	__m128i xa, ya;
	aligned_pod_array<uint32_t, 4, 32> H;
	while (processed < hss)
	{
		if (!total)
		{
			ROUND256(0);
			ROUND256(1);
			ROUND256(2);
			ROUND256(3);
			ROUND256(4);
			ROUND256(5);
			ROUND256(6);
		}
		pos = std::min(hss - processed, static_cast<size_t>(16));
		xa = _mm_shuffle_epi32(_mm256_castsi256_si128(Hx), 0b01010000);
		ya = _mm_shuffle_epi32(_mm256_castsi256_si128(Hy), 0b01010000);
		__m128i h = _mm_blend_epi32(ya, xa, 0b0101);

		_mm_store_si128((__m128i*) H.get(), h);
		memcpy(hash + processed, H.get(), pos);
		processed += pos;
		total = 0;
	}
}

void esch384_avx2_impl::final(unsigned char* hash, unsigned char* m, uint64_t& total, size_t& pos)
{
	total = 1;
	if (pos < 16)
	{
		memset(&m[pos], 0, 16 - pos);
		m[pos] = 0x80;
		HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0, 0, 0x1000000, 0, 0, 0));
	}
	else
		HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0, 0, 0x2000000, 0, 0, 0));

	transform(m, 1, true);

	size_t processed = 0;
	size_t hss = 384 / 8;
	__m256i Hx = HHx;
	__m256i Hy = HHy;
	__m128i xa, ya;
	aligned_pod_array<uint32_t, 4, 32> H;
	while (processed < hss)
	{
		if (!total)
		{
			ROUND384(0);
			ROUND384(1);
			ROUND384(2);
			ROUND384(3);
			ROUND384(4);
			ROUND384(5);
			ROUND384(6);
			ROUND384(7);
		}
		pos = std::min(hss - processed, static_cast<size_t>(16));
		xa = _mm_shuffle_epi32(_mm256_castsi256_si128(Hx), 0b01010000);
		ya = _mm_shuffle_epi32(_mm256_castsi256_si128(Hy), 0b01010000);
		__m128i h = _mm_blend_epi32(ya, xa, 0b0101);

		_mm_store_si128((__m128i*) H.get(), h);
		memcpy(hash + processed, H.get(), pos);
		processed += pos;
		total = 0;
	}
}

void esch256_avx2_impl::transform(const unsigned char* m, size_t num_blks, bool lastBlock)
{
	const uint32_t* M = reinterpret_cast<const uint32_t*>(m);
	__m256i Hx = HHx;
	__m256i Hy = HHy;
	__m128i xa, ya;
	for (size_t blk = 0; blk < num_blks; blk++)
	{
		uint32_t x = M[0] ^ M[2];
		uint32_t y = M[1] ^ M[3];
		x = rotater32(x ^ (x << 16), 16);
		y = rotater32(y ^ (y << 16), 16);

		Hx = _mm256_xor_si256(Hx, _mm256_zextsi128_si256(_mm_set_epi32(0, y, y, y)));
		Hy = _mm256_xor_si256(Hy, _mm256_zextsi128_si256(_mm_set_epi32(0, x, x, x)));
		Hx = _mm256_xor_si256(Hx, _mm256_set_epi32(0, 0, 0, 0, 0, 0, M[2], M[0]));
		Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, M[3], M[1]));
		ROUND256(0);
		ROUND256(1);
		ROUND256(2);
		ROUND256(3);
		ROUND256(4);
		ROUND256(5);
		ROUND256(6);
		if (lastBlock)
		{
			ROUND256(7);
			ROUND256(8);
			ROUND256(9);
			ROUND256(10);
		}
		M += 4;
	}
	HHx = Hx;
	HHy = Hy;
}

void esch384_avx2_impl::transform(const unsigned char* m, size_t num_blks, bool lastBlock)
{
	const uint32_t* M = reinterpret_cast<const uint32_t*>(m);
	__m256i Hx = HHx;
	__m256i Hy = HHy;
	__m128i xa, ya;
	for (size_t blk = 0; blk < num_blks; blk++)
	{
		uint32_t x = M[0] ^ M[2];
		uint32_t y = M[1] ^ M[3];
		x = rotater32(x ^ (x << 16), 16);
		y = rotater32(y ^ (y << 16), 16);

		Hx = _mm256_xor_si256(Hx, _mm256_zextsi128_si256(_mm_set1_epi32(y)));
		Hy = _mm256_xor_si256(Hy, _mm256_zextsi128_si256(_mm_set1_epi32(x)));
		Hx = _mm256_xor_si256(Hx, _mm256_set_epi32(0, 0, 0, 0, 0, 0, M[2], M[0]));
		Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, M[3], M[1]));
		ROUND384(0);
		ROUND384(1);
		ROUND384(2);
		ROUND384(3);
		ROUND384(4);
		ROUND384(5);
		ROUND384(6);
		ROUND384(7);
		if (lastBlock)
		{
			ROUND384(8);
			ROUND384(9);
			ROUND384(10);
			ROUND384(11);
		}
		M += 4;
	}
	HHx = Hx;
	HHy = Hy;
}


	}
}
