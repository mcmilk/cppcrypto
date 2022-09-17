/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "ctr-sse41.h"
#include <string.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

namespace cppcrypto
{
namespace detail
{
	void increment_and_encrypt8_block128(unsigned char* ctr, size_t nb, uint32_t** ctrs, uint32_t& counter, unsigned char* block, block_cipher* cipher)
	{
		__m128i mask = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
		unsigned char buf[128];
		memcpy(buf, ctr, 128);
		uint32_t myctr = counter;
		__m128i c = _mm_loadu_si128((const __m128i * )ctr);
		_mm_storeu_si128((__m128i*)buf, c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 16), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 32), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 48), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 64), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 80), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 96), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)(buf + 112), c);
		c = _mm_insert_epi32(c, ++myctr, 3);
		c = _mm_shuffle_epi8(c, mask);
		_mm_storeu_si128((__m128i*)ctr, c);
		counter = myctr;
		cipher->encrypt_blocks(buf, block, 8);
	}

}
}
