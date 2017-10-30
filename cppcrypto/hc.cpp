/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "hc.h"
#include "cpuinfo.h"
#include <assert.h>
#include <memory.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include "portability.h"
#include <algorithm>

#ifdef _MSC_VER
#define inline __forceinline
#endif

//#define CPPCRYPTO_DEBUG

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


	static inline uint32_t f1(uint32_t x)
	{
		return rotater32(x, 7) ^ rotater32(x, 18) ^ (x >> 3);
	}

	static inline uint32_t f2(uint32_t x)
	{
		return rotater32(x, 17) ^ rotater32(x, 19) ^ (x >> 10);
	}

	static inline uint32_t g1(uint32_t x, uint32_t y, uint32_t* Q)
	{
		return (rotater32(x, 10) ^ rotater32(y, 23)) + Q[(x ^ y) & 0x3ff];
	}

	static inline uint32_t h1(uint32_t x, uint32_t* Q)
	{
		return Q[(unsigned char)(x)] + Q[256 + (unsigned char)(x >> 8)] + Q[512 + (unsigned char)(x >> 16)] + Q[768 + (unsigned char)(x >> 24)];
	}

	static inline void P32(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + X[(x + 6) % 16] + g1(X[(x + 13) % 16], P[i + 1 + x], Q);
		X[x] = P[i + x];
	}

	static inline void P32L(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + X[(x + 6) % 16] + g1(X[(x + 13) % 16], P[i == 1008 ? 0 : i + 1 + x], Q);
		X[x] = P[i + x];
	}

	static inline void P32(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P32(P, Q, X, i, x);
		block[x] = h1(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void P32L(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P32L(P, Q, X, i, x);
		block[x] = h1(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void gen_block(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i)
	{
		P32(P, Q, X, block, i, 0);
		P32(P, Q, X, block, i, 1);
		P32(P, Q, X, block, i, 2);
		P32(P, Q, X, block, i, 3);
		P32(P, Q, X, block, i, 4);
		P32(P, Q, X, block, i, 5);
		P32(P, Q, X, block, i, 6);
		P32(P, Q, X, block, i, 7);
		P32(P, Q, X, block, i, 8);
		P32(P, Q, X, block, i, 9);
		P32(P, Q, X, block, i, 10);
		P32(P, Q, X, block, i, 11);
		P32(P, Q, X, block, i, 12);
		P32(P, Q, X, block, i, 13);
		P32(P, Q, X, block, i, 14);
		P32L(P, Q, X, block, i, 15);
	}

	static inline void gen_block(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i)
	{
		P32(P, Q, X, i, 0);
		P32(P, Q, X, i, 1);
		P32(P, Q, X, i, 2);
		P32(P, Q, X, i, 3);
		P32(P, Q, X, i, 4);
		P32(P, Q, X, i, 5);
		P32(P, Q, X, i, 6);
		P32(P, Q, X, i, 7);
		P32(P, Q, X, i, 8);
		P32(P, Q, X, i, 9);
		P32(P, Q, X, i, 10);
		P32(P, Q, X, i, 11);
		P32(P, Q, X, i, 12);
		P32(P, Q, X, i, 13);
		P32(P, Q, X, i, 14);
		P32L(P, Q, X, i, 15);
	}

	static inline void generate_block(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* Y, uint32_t* block_, uint32_t& words)
	{
		uint32_t i = words;
		if (words < 1024)
		{
			gen_block(P, Q, X, block_, i);
			words += 16;
		}
		else
		{
			gen_block(Q, P, Y, block_, i - 1024);
			words += 16;
			if (words == 2048)
				words = 0;
		}
	}

	static inline void generate_block(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* Y, uint32_t& words)
	{
		uint32_t i = words;
		if (words < 1024)
		{
			gen_block(P, Q, X, i);
			words += 16;
		}
		else
		{
			gen_block(Q, P, Y, i - 1024);
			words += 16;
			if (words == 2048)
				words = 0;
		}
	}


	hc256::hc256()
		: pos(0)
	{
	}

	hc256::~hc256()
	{
		clear();
	}

	void hc256::clear()
	{
		zero_memory(block_, sizeof(block_));
		zero_memory(P, sizeof(P));
		zero_memory(Q, sizeof(Q));
		zero_memory(X, sizeof(X));
		zero_memory(Y, sizeof(Y));
	}

	void hc256::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		size_t i = 0;
		if (pos)
		{
			while (pos < len && pos < 64)
			{
				out[i] = in[i] ^ ((unsigned char*)block_)[pos++];
				++i;
			}
			len -= i;
		}
		if (len)
			pos = 0;
		for (; len; len -= std::min(static_cast<size_t>(64), len))
		{
			generate_block(P, Q, X, Y, block_, words);
			if (len >= 64)
			{
				xor_block_512(in + i, (unsigned char*)block_, out + i);
				i += 64;
			}
			else
			{
				for (; pos < len; pos++, i++)
					out[i] = in[i] ^ ((unsigned char*)block_)[pos];
			}
		}
	}

	void hc256::decrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		return encrypt(in, len, out);
	}

	void hc256::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 32);

		uint32_t W[2560];
		W[0] = *(uint32_t*)key;
		W[1] = *(uint32_t*)(key + 4);
		W[2] = *(uint32_t*)(key + 8);
		W[3] = *(uint32_t*)(key + 12);
		W[4] = *(uint32_t*)(key + 16);
		W[5] = *(uint32_t*)(key + 20);
		W[6] = *(uint32_t*)(key + 24);
		W[7] = *(uint32_t*)(key + 28);
		W[8] = *(uint32_t*)iv;
		W[9] = *(uint32_t*)(iv + 4);
		W[10] = *(uint32_t*)(iv + 8);
		W[11] = *(uint32_t*)(iv + 12);
		W[12] = *(uint32_t*)(iv + 16);
		W[13] = *(uint32_t*)(iv + 20);
		W[14] = *(uint32_t*)(iv + 24);
		W[15] = *(uint32_t*)(iv + 28);
		for (int i = 16; i < 2560; i++)
			W[i] = f2(W[i - 2]) + W[i - 7] + f1(W[i - 15]) + W[i - 16] + i;

		memcpy(P, &W[512], sizeof(P));
		memcpy(Q, &W[1536], sizeof(Q));
		memcpy(X, &P[1024 - 16], sizeof(X));
		memcpy(Y, &Q[1024 - 16], sizeof(Y));
		
#ifdef CPPCRYPTO_DEBUG
		printf("pre-4096:\n");
		for (int i = 0; i < 1024; i++)
			printf("P[%d] = %08x, Q[%d] = %08x\n", i, P[i], i, Q[i]);
#endif

		words = 0;
		pos = 0;
		for (int i = 0; i < 4096 / 16; i++)
			generate_block(P, Q, X, Y, words);

#ifdef CPPCRYPTO_DEBUG
		printf("post-4096:\n");
		for (int i = 0; i < 1024; i++)
			printf("P[%d] = %08x, Q[%d] = %08x\n", i, P[i], i, Q[i]);
#endif
	}

	static inline uint32_t g1_128(uint32_t x, uint32_t y, uint32_t z)
	{
		return (rotater32(x, 10) ^ rotater32(z, 23)) + rotater32(y, 8);
	}

	static inline uint32_t g2_128(uint32_t x, uint32_t y, uint32_t z)
	{
		return (rotatel32(x, 10) ^ rotatel32(z, 23)) + rotatel32(y, 8);
	}

	static inline uint32_t h1_128(uint32_t x, uint32_t* Q)
	{
		return Q[(unsigned char)(x)] + Q[256 + (unsigned char)(x >> 16)];
	}

	static inline void P32_128_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = (P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q);
		X[x] = P[i + x];
	}

	static inline void P32_128L_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = (P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i == 496 ? 0 : i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q);
		X[x] = P[i + x];
	}

	static inline void P32_128_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x]);
		X[x] = P[i + x];
		block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void P32_128L_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + g1_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i == 496 ? 0 : i + 1 + x]);
		X[x] = P[i + x];
		block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void gen_block_128_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i)
	{
		P32_128_P(P, Q, X, block, i, 0);
		P32_128_P(P, Q, X, block, i, 1);
		P32_128_P(P, Q, X, block, i, 2);
		P32_128_P(P, Q, X, block, i, 3);
		P32_128_P(P, Q, X, block, i, 4);
		P32_128_P(P, Q, X, block, i, 5);
		P32_128_P(P, Q, X, block, i, 6);
		P32_128_P(P, Q, X, block, i, 7);
		P32_128_P(P, Q, X, block, i, 8);
		P32_128_P(P, Q, X, block, i, 9);
		P32_128_P(P, Q, X, block, i, 10);
		P32_128_P(P, Q, X, block, i, 11);
		P32_128_P(P, Q, X, block, i, 12);
		P32_128_P(P, Q, X, block, i, 13);
		P32_128_P(P, Q, X, block, i, 14);
		P32_128L_P(P, Q, X, block, i, 15);
	}

	static inline void P32_128_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = (P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q);
		X[x] = P[i + x];
	}

	static inline void P32_128L_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i, const uint32_t x)
	{
		P[i + x] = (P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i == 496 ? 0 : i + 1 + x])) ^ h1_128(X[(x + 4) % 16], Q);
		X[x] = P[i + x];
	}

	static inline void P32_128_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i + 1 + x]);
		X[x] = P[i + x];
		block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void P32_128L_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i, const uint32_t x)
	{
		P[i + x] = P[i + x] + g2_128(X[(x + 13) % 16], X[(x + 6) % 16], P[i == 496 ? 0 : i + 1 + x]);
		X[x] = P[i + x];
		block[x] = h1_128(X[(x + 4) % 16], Q) ^ P[i + x];
	}

	static inline void gen_block_128_P(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i)
	{
		P32_128_P(P, Q, X, i, 0);
		P32_128_P(P, Q, X, i, 1);
		P32_128_P(P, Q, X, i, 2);
		P32_128_P(P, Q, X, i, 3);
		P32_128_P(P, Q, X, i, 4);
		P32_128_P(P, Q, X, i, 5);
		P32_128_P(P, Q, X, i, 6);
		P32_128_P(P, Q, X, i, 7);
		P32_128_P(P, Q, X, i, 8);
		P32_128_P(P, Q, X, i, 9);
		P32_128_P(P, Q, X, i, 10);
		P32_128_P(P, Q, X, i, 11);
		P32_128_P(P, Q, X, i, 12);
		P32_128_P(P, Q, X, i, 13);
		P32_128_P(P, Q, X, i, 14);
		P32_128L_P(P, Q, X, i, 15);
	}

	static inline void gen_block_128_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* block, uint32_t i)
	{
		P32_128_Q(P, Q, X, block, i, 0);
		P32_128_Q(P, Q, X, block, i, 1);
		P32_128_Q(P, Q, X, block, i, 2);
		P32_128_Q(P, Q, X, block, i, 3);
		P32_128_Q(P, Q, X, block, i, 4);
		P32_128_Q(P, Q, X, block, i, 5);
		P32_128_Q(P, Q, X, block, i, 6);
		P32_128_Q(P, Q, X, block, i, 7);
		P32_128_Q(P, Q, X, block, i, 8);
		P32_128_Q(P, Q, X, block, i, 9);
		P32_128_Q(P, Q, X, block, i, 10);
		P32_128_Q(P, Q, X, block, i, 11);
		P32_128_Q(P, Q, X, block, i, 12);
		P32_128_Q(P, Q, X, block, i, 13);
		P32_128_Q(P, Q, X, block, i, 14);
		P32_128L_Q(P, Q, X, block, i, 15);
	}

	static inline void gen_block_128_Q(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t i)
	{
		P32_128_Q(P, Q, X, i, 0);
		P32_128_Q(P, Q, X, i, 1);
		P32_128_Q(P, Q, X, i, 2);
		P32_128_Q(P, Q, X, i, 3);
		P32_128_Q(P, Q, X, i, 4);
		P32_128_Q(P, Q, X, i, 5);
		P32_128_Q(P, Q, X, i, 6);
		P32_128_Q(P, Q, X, i, 7);
		P32_128_Q(P, Q, X, i, 8);
		P32_128_Q(P, Q, X, i, 9);
		P32_128_Q(P, Q, X, i, 10);
		P32_128_Q(P, Q, X, i, 11);
		P32_128_Q(P, Q, X, i, 12);
		P32_128_Q(P, Q, X, i, 13);
		P32_128_Q(P, Q, X, i, 14);
		P32_128L_Q(P, Q, X, i, 15);
	}

	static inline void generate_block_128(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* Y, uint32_t* block_, uint32_t& words)
	{
		uint32_t i = words;
		if (words < 512)
		{
			gen_block_128_P(P, Q, X, block_, i);
			words += 16;
		}
		else
		{
			gen_block_128_Q(Q, P, Y, block_, i - 512);
			words += 16;
			if (words == 1024)
				words = 0;
		}
	}

	static inline void generate_block_128(uint32_t* P, uint32_t* Q, uint32_t* X, uint32_t* Y, uint32_t& words)
	{
		uint32_t i = words;
		if (words < 512)
		{
			gen_block_128_P(P, Q, X, i);
			words += 16;
		}
		else
		{
			gen_block_128_Q(Q, P, Y, i - 512);
			words += 16;
			if (words == 1024)
				words = 0;
		}
	}

	void hc128::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == keysize() / 8);
		assert(ivlen == 16);

		uint32_t W[1280];
		W[0] = *(uint32_t*)key;
		W[1] = *(uint32_t*)(key + 4);
		W[2] = *(uint32_t*)(key + 8);
		W[3] = *(uint32_t*)(key + 12);
		W[4] = *(uint32_t*)(key);
		W[5] = *(uint32_t*)(key + 4);
		W[6] = *(uint32_t*)(key + 8);
		W[7] = *(uint32_t*)(key + 12);
		W[8] = *(uint32_t*)iv;
		W[9] = *(uint32_t*)(iv + 4);
		W[10] = *(uint32_t*)(iv + 8);
		W[11] = *(uint32_t*)(iv + 12);
		W[12] = *(uint32_t*)(iv);
		W[13] = *(uint32_t*)(iv + 4);
		W[14] = *(uint32_t*)(iv + 8);
		W[15] = *(uint32_t*)(iv + 12);
		for (int i = 16; i < 1280; i++)
			W[i] = f2(W[i - 2]) + W[i - 7] + f1(W[i - 15]) + W[i - 16] + i;

		memcpy(P, &W[256], sizeof(P));
		memcpy(Q, &W[768], sizeof(Q));
		memcpy(X, &P[512 - 16], sizeof(X));
		memcpy(Y, &Q[512 - 16], sizeof(Y));

#ifdef CPPCRYPTO_DEBUG
		printf("pre-1024:\n");
		for (int i = 0; i < 512; i++)
			printf("P[%d] = %08x, Q[%d] = %08x\n", i, P[i], i, Q[i]);
#endif

		words = 0;
		pos = 0;
		for (int i = 0; i < 1024 / 16; i++)
			generate_block_128(P, Q, X, Y, words);

#ifdef CPPCRYPTO_DEBUG
		printf("post-1024:\n");
		for (int i = 0; i < 512; i++)
			printf("P[%d] = %08x, Q[%d] = %08x\n", i, P[i], i, Q[i]);
#endif
	}

	hc128::hc128()
		: pos(0)
	{
	}

	hc128::~hc128()
	{
		clear();
	}

	void hc128::clear()
	{
		zero_memory(block_, sizeof(block_));
		zero_memory(P, sizeof(P));
		zero_memory(Q, sizeof(Q));
		zero_memory(X, sizeof(X));
		zero_memory(Y, sizeof(Y));
	}

	void hc128::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		size_t i = 0;
		if (pos)
		{
			while (pos < len && pos < 64)
			{
				out[i] = in[i] ^ ((unsigned char*)block_)[pos++];
				++i;
			}
			len -= i;
		}
		if (len)
			pos = 0;
		for (; len; len -= std::min(static_cast<size_t>(64), len))
		{
			generate_block_128(P, Q, X, Y, block_, words);
			if (len >= 64)
			{
				xor_block_512(in + i, (unsigned char*)block_, out + i);
				i += 64;
			}
			else
			{
				for (; pos < len; pos++, i++)
					out[i] = in[i] ^ ((unsigned char*)block_)[pos];
			}
		}
	}

	void hc128::decrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		return encrypt(in, len, out);
	}

}
