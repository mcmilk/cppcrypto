/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "chacha.h"
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
	void chacha_ECRYPT_encrypt_bytes(size_t bytes, uint32_t* x, const unsigned char* m, unsigned char* out, unsigned char* output, unsigned int r);
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
			if (cpu_info::ssse3())
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

	static inline void chacha_core(uint32_t* x, int r)
	{
		for (int i = 0; i < r; i++)
		{
			x[0] += x[4];
			x[12] = rotatel32(x[12] ^ x[0], 16);
			x[8] += x[12];
			x[4] = rotatel32(x[4] ^ x[8], 12);
			x[0] += x[4];
			x[12] = rotatel32(x[12] ^ x[0], 8);
			x[8] += x[12];
			x[4] = rotatel32(x[4] ^ x[8], 7);

			x[1] += x[5];
			x[13] = rotatel32(x[13] ^ x[1], 16);
			x[9] += x[13];
			x[5] = rotatel32(x[5] ^ x[9], 12);
			x[1] += x[5];
			x[13] = rotatel32(x[13] ^ x[1], 8);
			x[9] += x[13];
			x[5] = rotatel32(x[5] ^ x[9], 7);

			x[2] += x[6];
			x[14] = rotatel32(x[14] ^ x[2], 16);
			x[10] += x[14];
			x[6] = rotatel32(x[6] ^ x[10], 12);
			x[2] += x[6];
			x[14] = rotatel32(x[14] ^ x[2], 8);
			x[10] += x[14];
			x[6] = rotatel32(x[6] ^ x[10], 7);

			x[3] += x[7];
			x[15] = rotatel32(x[15] ^ x[3], 16);
			x[11] += x[15];
			x[7] = rotatel32(x[7] ^ x[11], 12);
			x[3] += x[7];
			x[15] = rotatel32(x[15] ^ x[3], 8);
			x[11] += x[15];
			x[7] = rotatel32(x[7] ^ x[11], 7);

			x[0] += x[5];
			x[15] = rotatel32(x[15] ^ x[0], 16);
			x[10] += x[15];
			x[5] = rotatel32(x[5] ^ x[10], 12);
			x[0] += x[5];
			x[15] = rotatel32(x[15] ^ x[0], 8);
			x[10] += x[15];
			x[5] = rotatel32(x[5] ^ x[10], 7);

			x[1] += x[6];
			x[12] = rotatel32(x[12] ^ x[1], 16);
			x[11] += x[12];
			x[6] = rotatel32(x[6] ^ x[11], 12);
			x[1] += x[6];
			x[12] = rotatel32(x[12] ^ x[1], 8);
			x[11] += x[12];
			x[6] = rotatel32(x[6] ^ x[11], 7);

			x[2] += x[7];
			x[13] = rotatel32(x[13] ^ x[2], 16);
			x[8] += x[13];
			x[7] = rotatel32(x[7] ^ x[8], 12);
			x[2] += x[7];
			x[13] = rotatel32(x[13] ^ x[2], 8);
			x[8] += x[13];
			x[7] = rotatel32(x[7] ^ x[8], 7);

			x[3] += x[4];
			x[14] = rotatel32(x[14] ^ x[3], 16);
			x[9] += x[14];
			x[4] = rotatel32(x[4] ^ x[9], 12);
			x[3] += x[4];
			x[14] = rotatel32(x[14] ^ x[3], 8);
			x[9] += x[14];
			x[4] = rotatel32(x[4] ^ x[9], 7);
		}
	}

	static inline void chacha_hash(const uint32_t* in, uint32_t* out, int r)
	{
		uint32_t x[16];
		memcpy(x, in, 64);
		chacha_core(x, r);
		for (int i = 0; i < 16; ++i)
			out[i] = x[i] + in[i];
	}

	chacha20_256::chacha20_256()
		: pos(0)
	{
	}

	chacha20_256::~chacha20_256()
	{
		clear();
	}

	void chacha20_256::clear()
	{
		zero_memory(block_, sizeof(block_));
		zero_memory(input_, sizeof(input_));
	}

	static inline void incrementSalsaCounter(uint32_t* input, uint32_t* block, int r)
	{
		chacha_hash(input, block, r);
		if (!++input[12])
			++input[13];
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
		if (cpu_info::ssse3())
		{
			size_t fullblocks = len - len % 64;
			if (fullblocks)
			{
				chacha_ECRYPT_encrypt_bytes(fullblocks, input, in + i, out + i, (unsigned char*)block, r);
				i += fullblocks;
				len -= fullblocks;
			}
			if (len)
			{
				chacha_ECRYPT_encrypt_bytes(len, input, in + i, out + i, (unsigned char*)block, r);
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

	void chacha20_256::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 10, pos, input_, block_);
	}

	void chacha20_256::decrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		return encrypt(in, len, out);
	}

	void chacha20_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 8 || ivlen == 12);

		input_[12] = 0;
		input_[13] = 0;
		memcpy(input_ + 4, key, 32);
		memcpy(input_ + (ivlen == 12 ? 13 : 14), iv, ivlen);
		input_[0] = 0x61707865;
		input_[1] = 0x3320646E;
		input_[2] = 0x79622D32;
		input_[3] = 0x6B206574;
		pos = 0;
	}

	void chacha20_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 8 || ivlen == 12);

		input_[12] = 0;
		input_[13] = 0;
		memcpy(input_ + 4, key, 16);
		memcpy(input_ + 8, key, 16);
		memcpy(input_ + (ivlen == 12 ? 13 : 14), iv, ivlen);
		input_[0] = 0x61707865;
		input_[1] = 0x3120646E;
		input_[2] = 0x79622D36;
		input_[3] = 0x6B206574;

		pos = 0;
	}

	static inline void hchacha_hash(const uint32_t* in, uint32_t* out, int r)
	{
		uint32_t x[16];
		memcpy(x, in, 64);
		chacha_core(x, r);
		out[0] = x[0];
		out[1] = x[1];
		out[2] = x[2];
		out[3] = x[3];
		out[4] = x[12];
		out[5] = x[13];
		out[6] = x[14];
		out[7] = x[15];
	}

	static inline void do_xchacha_128_init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, int r, uint32_t* input, size_t& pos)
	{
		assert(keylen == 128 / 8);
		assert(ivlen == 24);

		uint32_t tmp[8];
		memcpy(input + 4, key, 16);
		memcpy(input + 8, key, 16);
		memcpy(input + 12, iv, 16);
		input[0] = 0x61707865;
		input[1] = 0x3120646E;
		input[2] = 0x79622D36;
		input[3] = 0x6B206574;
		pos = 0;

		hchacha_hash(input, tmp, r);

		memcpy(input + 4, tmp, 32);
		memcpy(input + 14, iv + 16, 8);
		input[12] = 0;
		input[13] = 0;
	}

	static inline void do_xchacha_256_init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, int r, uint32_t* input, size_t& pos)
	{
		assert(keylen == 256 / 8);
		assert(ivlen == 24);

		uint32_t tmp[8];
		memcpy(input + 4, key, 32);
		memcpy(input + 12, iv, 16);
		input[0] = 0x61707865;
		input[1] = 0x3320646E;
		input[2] = 0x79622D32;
		input[3] = 0x6B206574;
		pos = 0;

		hchacha_hash(input, tmp, r);

		memcpy(input + 4, tmp, 32);
		memcpy(input + 14, iv + 16, 8);
		input[12] = 0;
		input[13] = 0;
	}

	void xchacha20_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xchacha_256_init(key, keylen, iv, ivlen, 10, input_, pos);
	}

	void xchacha20_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xchacha_128_init(key, keylen, iv, ivlen, 10, input_, pos);
	}

	void chacha12_256::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 6, pos, input_, block_);
	}

	void chacha12_128::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		do_encrypt(in, len, out, 6, pos, input_, block_);
	}

	void xchacha12_256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xchacha_256_init(key, keylen, iv, ivlen, 6, input_, pos);
	}

	void xchacha12_128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		do_xchacha_128_init(key, keylen, iv, ivlen, 6, input_, pos);
	}

}
