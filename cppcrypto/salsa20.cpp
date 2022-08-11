/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "salsa20.h"
#include "cpuinfo.h"
#include <assert.h>
#include <memory.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include "portability.h"
#include <algorithm>

//#define NO_OPTIMIZED_VERSIONS

extern "C"
{
	void salsa20_ECRYPT_encrypt_bytes(size_t bytes, uint32_t* x, const unsigned char* m, unsigned char* out, unsigned char* output, unsigned int r);
}

namespace cppcrypto
{
	static inline void xor_block_512(const unsigned char* in, const unsigned char* prev, unsigned char* out)
	{
#ifdef USE_AVX
		if (cpu_info::avx())
		{
			__m256i b1 = _mm256_loadu_si256((const __m256i*) in);
			__m256i p1 = _mm256_loadu_si256((const __m256i*) prev);
			__m256i b2 = _mm256_loadu_si256((const __m256i*) (in + 32));
			__m256i p2 = _mm256_loadu_si256((const __m256i*) (prev + 32));

			_mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(b1, p1));
			_mm256_storeu_si256((__m256i*) (out + 32), _mm256_xor_si256(b2, p2));
			_mm256_zeroupper();
		}
		else
#endif
			if (cpu_info::sse2())
			{
				__m128i b1 = _mm_loadu_si128((const __m128i*) in);
				__m128i p1 = _mm_loadu_si128((const __m128i*) prev);
				__m128i b2 = _mm_loadu_si128((const __m128i*) (in + 16));
				__m128i p2 = _mm_loadu_si128((const __m128i*) (prev + 16));

				_mm_storeu_si128((__m128i*) out, _mm_xor_si128(b1, p1));
				_mm_storeu_si128((__m128i*) (out + 16), _mm_xor_si128(b2, p2));

				b1 = _mm_loadu_si128((const __m128i*) (in + 32));
				p1 = _mm_loadu_si128((const __m128i*) (prev + 32));
				b2 = _mm_loadu_si128((const __m128i*) (in + 48));
				p2 = _mm_loadu_si128((const __m128i*) (prev + 48));

				_mm_storeu_si128((__m128i*) (out + 32), _mm_xor_si128(b1, p1));
				_mm_storeu_si128((__m128i*) (out + 48), _mm_xor_si128(b2, p2));

			}
			else {
				for (int i = 0; i < 64; i++)
					out[i] = in[i] ^ prev[i];
			}

	}

	static inline void salsa20_core(uint32_t* x, int r)
	{
		for (int i = 0; i < r; i++)
		{
			x[4] ^= rotatel32(x[0] + x[12], 7);
			x[8] ^= rotatel32(x[4] + x[0], 9);
			x[12] ^= rotatel32(x[8] + x[4], 13);
			x[0] ^= rotatel32(x[12] + x[8], 18);
			x[9] ^= rotatel32(x[5] + x[1], 7);
			x[13] ^= rotatel32(x[9] + x[5], 9);
			x[1] ^= rotatel32(x[13] + x[9], 13);
			x[5] ^= rotatel32(x[1] + x[13], 18);
			x[14] ^= rotatel32(x[10] + x[6], 7);
			x[2] ^= rotatel32(x[14] + x[10], 9);
			x[6] ^= rotatel32(x[2] + x[14], 13);
			x[10] ^= rotatel32(x[6] + x[2], 18);
			x[3] ^= rotatel32(x[15] + x[11], 7);
			x[7] ^= rotatel32(x[3] + x[15], 9);
			x[11] ^= rotatel32(x[7] + x[3], 13);
			x[15] ^= rotatel32(x[11] + x[7], 18);
			x[1] ^= rotatel32(x[0] + x[3], 7);
			x[2] ^= rotatel32(x[1] + x[0], 9);
			x[3] ^= rotatel32(x[2] + x[1], 13);
			x[0] ^= rotatel32(x[3] + x[2], 18);
			x[6] ^= rotatel32(x[5] + x[4], 7);
			x[7] ^= rotatel32(x[6] + x[5], 9);
			x[4] ^= rotatel32(x[7] + x[6], 13);
			x[5] ^= rotatel32(x[4] + x[7], 18);
			x[11] ^= rotatel32(x[10] + x[9], 7);
			x[8] ^= rotatel32(x[11] + x[10], 9);
			x[9] ^= rotatel32(x[8] + x[11], 13);
			x[10] ^= rotatel32(x[9] + x[8], 18);
			x[12] ^= rotatel32(x[15] + x[14], 7);
			x[13] ^= rotatel32(x[12] + x[15], 9);
			x[14] ^= rotatel32(x[13] + x[12], 13);
			x[15] ^= rotatel32(x[14] + x[13], 18);
		}
	}

	static inline void salsa20_hash(const uint32_t* in, uint32_t* out, int r)
	{
		uint32_t x[16];
		memcpy(x, in, 64);
		salsa20_core(x, r);
		for (int i = 0; i < 16; ++i)
			out[i] = x[i] + in[i];
	}

	salsa20_256::salsa20_256()
		: pos(0)
	{
	}

	salsa20_256::~salsa20_256()
	{
		clear();
	}

	void salsa20_256::clear()
	{
		zero_memory(block_, sizeof(block_));
		zero_memory(input_, sizeof(input_));
	}

	static inline void incrementSalsaCounter(uint32_t* input, uint32_t* block, int r)
	{
		salsa20_hash(input, block, r);
		if (!++input[8])
			++input[9];
	}

	static inline void do_encrypt(const unsigned char* in, size_t len, unsigned char* out, int r, size_t& pos, uint32_t* input, uint32_t* block)
	{
		size_t i = 0;
		if (pos)
		{
			while (pos < len && pos < 64)
			{
				out[i] = in[i] ^ ((unsigned char*)block)[pos++];
				++i;
			}
			len -= i;
		}
		if (len)
			pos = 0;
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
		{
			size_t fullblocks = len - len % 64;
			if (fullblocks)
			{
				salsa20_ECRYPT_encrypt_bytes(fullblocks, input, in + i, out + i, (unsigned char*)block, r);
				i += fullblocks;
				len -= fullblocks;
			}
			if (len)
			{
				salsa20_ECRYPT_encrypt_bytes(len, input, in + i, out + i, (unsigned char*)block, r);
				pos = len;
			}
			return;
		}
#endif
		for (; len; len -= std::min(static_cast<size_t>(64), len))
		{
			incrementSalsaCounter(input, block, r);
			if (len >= 64)
			{
				xor_block_512(in + i, (unsigned char*)block, out + i);
				i += 64;
			}
			else
			{
				for (; pos < len; pos++, i++)
					out[i] = in[i] ^ ((unsigned char*)block)[pos];
			}
		}
	}

	void salsa20_256::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 10, pos, input_, block_);
	}

	void salsa20_256::decrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		return encrypt(in, len, out);
	}

	static inline void transform_input_for_sse(uint32_t* input)
	{
		uint32_t tmp[16];
		memcpy(tmp, input, sizeof(tmp));
		static const int tr[16] = { 0, 5, 10, 15, 12, 1, 6, 11, 8, 13, 2, 7, 4, 9, 14, 3 };
		for (int i = 0; i < 16; i++)
			input[tr[i]] = tmp[i];
	}

	void salsa20_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 8);

		memcpy(input_ + 1, key, 16);
		memcpy(input_ + 6, iv, ivlen);
		input_[0] = 0x61707865;
		input_[15] = 0x6B206574;
		input_[8] = 0;
		input_[9] = 0;
		memcpy(input_ + 11, key + 16, 16);
		input_[5] = 0x3320646E;
		input_[10] = 0x79622D32;
		pos = 0;

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			transform_input_for_sse(input_);
#endif
	}

	void salsa20_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 8);

		memcpy(input_ + 1, key, 16);
		memcpy(input_ + 6, iv, ivlen);
		input_[0] = 0x61707865;
		input_[15] = 0x6B206574;
		input_[8] = 0;
		input_[9] = 0;
		memcpy(input_ + 11, key, 16);
		input_[5] = 0x3120646E;
		input_[10] = 0x79622D36;

		pos = 0;

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			transform_input_for_sse(input_);
#endif
	}

	static inline void hsalsa20_hash(const uint32_t* in, uint32_t* out, int r)
	{
		uint32_t x[16];
		memcpy(x, in, 64);
		salsa20_core(x, r);
		out[0] = x[0];
		out[1] = x[5];
		out[2] = x[10];
		out[3] = x[15];
		out[4] = x[6];
		out[5] = x[7];
		out[6] = x[8];
		out[7] = x[9];
	}

	static inline void do_xsalsa20_128_init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, int r, uint32_t* input, size_t& pos)
	{
		assert(keylen == 128 / 8);
		assert(ivlen == 24);

		uint32_t tmp[8];
		memcpy(input + 1, key, 16);
		memcpy(input + 6, iv, 16);
		input[0] = 0x61707865;
		input[15] = 0x6B206574;
		memcpy(input + 11, key, 16);
		input[5] = 0x3120646E;
		input[10] = 0x79622D36;
		pos = 0;

		hsalsa20_hash(input, tmp, r);

		memcpy(input + 1, tmp, 16);
		memcpy(input + 6, iv + 16, 8);
		input[8] = 0;
		input[9] = 0;
		memcpy(input + 11, tmp + 4, 16);

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			transform_input_for_sse(input);
#endif
	}

	static inline void do_xsalsa20_256_init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, int r, uint32_t* input, size_t& pos)
	{
		assert(keylen == 256 / 8);
		assert(ivlen == 24);

		uint32_t tmp[8];
		memcpy(input + 1, key, 16);
		memcpy(input + 6, iv, 16);
		input[0] = 0x61707865;
		input[15] = 0x6B206574;
		memcpy(input + 11, key + 16, 16);
		input[5] = 0x3320646E;
		input[10] = 0x79622D32;
		pos = 0;

		hsalsa20_hash(input, tmp, r);

		memcpy(input + 1, tmp, 16);
		memcpy(input + 6, iv + 16, 8);
		input[8] = 0;
		input[9] = 0;
		memcpy(input + 11, tmp + 4, 16);

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			transform_input_for_sse(input);
#endif
	}

	void xsalsa20_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xsalsa20_256_init(key, keylen, iv, ivlen, 10, input_, pos);
	}

	void xsalsa20_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xsalsa20_128_init(key, keylen, iv, ivlen, 10, input_, pos);
	}

	void salsa20_12_256::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 6, pos, input_, block_);
	}

	void salsa20_12_128::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 6, pos, input_, block_);
	}

	void xsalsa20_12_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xsalsa20_256_init(key, keylen, iv, ivlen, 6, input_, pos);
	}

	void xsalsa20_12_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xsalsa20_128_init(key, keylen, iv, ivlen, 6, input_, pos);
	}


}
