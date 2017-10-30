/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "sha256.h"
#include "portability.h"
#include <memory.h>
#include <functional>

//#define CPPCRYPTO_DEBUG

#ifdef _M_X64
extern "C"
{
	void sha256_sse4(void *input_data, uint32_t digest[8], uint64_t num_blks);
	void sha256_rorx(void *input_data, uint32_t digest[8], uint64_t num_blks);
#ifndef _MSC_VER
}
#endif
#if defined(_MSC_VER) || defined(INLINE_AS)
	void FASTCALL X86_SHA256_HashBlocks(uint32_t *state, const uint32_t *data, size_t len);
#endif
#ifdef _MSC_VER
}
#endif
#else
//	void sha256_sse4_intr(void *input_data, uint32_t digest[8], uint64_t num_blks);
#if defined(_MSC_VER) || defined(INLINE_AS)
	void FASTCALL X86_SHA256_HashBlocks(uint32_t *state, const uint32_t *data, size_t len);
#endif
#endif

namespace cppcrypto
{
	sha256::~sha256()
	{
		clear();
	}

	sha256::sha256()
	{
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef _M_X64
		if (cpu_info::avx2() && cpu_info::bmi2())
			transfunc = [this](void* m, uint64_t num_blks)
		{
			if (num_blks > 1)
				sha256_rorx(m, H, num_blks);
			else
				sha256_sse4(m, H, num_blks);
		};
		else 
		if (cpu_info::sse41())
#ifdef NO_BIND_TO_FUNCTION
			transfunc = [this](void* m, uint64_t num_bkls) { sha256_sse4(m, H.get(), num_bkls); };
#else
			transfunc = std::bind(&sha256_sse4, std::placeholders::_1, H.get(), std::placeholders::_2);
#endif
		else
#else
#if 0

		if (InstructionSet::sse41())
			transfunc = std::bind(&sha256_sse4_intr, std::placeholders::_1, H.get(), std::placeholders::_2);
		else
#endif
#endif
#if defined(_MSC_VER) || defined(INLINE_AS)
			if (cpu_info::sse2())
				transfunc = [this](void* m, uint64_t num_blks)
			{
				X86_SHA256_HashBlocks(H, (const uint32_t*)m, static_cast<size_t>(num_blks * 64));
			};
			else
#endif
#endif
#ifdef NO_BIND_TO_FUNCTION
		transfunc = [this](void* m, uint64_t num_blks) { transform(m, num_blks); };
#else
		transfunc = std::bind(&sha256::transform, this, std::placeholders::_1, std::placeholders::_2);
#endif
	}

	extern const
#ifdef _MSC_VER
 __declspec(align(16)) 
#else
__attribute__ ((aligned (16)))
#endif
	uint32_t SHA256_K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	static inline uint32_t rotr(uint32_t x, int n)
	{
		return (x >> n) | (x << (32 - n));
	}

	static inline uint32_t shr(uint32_t x, int n)
	{
		return x >> n;
	}

	static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (~x & z);
	}

	static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	static inline uint32_t sum0(uint32_t x)
	{
		return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
	}

	static inline uint32_t sum1(uint32_t x)
	{
		return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
	}

	static inline uint32_t sigma0(uint32_t x)
	{
		return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
	}

	static inline uint32_t sigma1(uint32_t x)
	{
		return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
	}

	void sha256::update(const unsigned char* data, size_t len)
	{
		if (pos && pos + len >= 64)
		{
			memcpy(&m[0] + pos, data, 64 - pos);
			transfunc(&m[0], 1);
			len -= 64 - pos;
			total += (64 - pos) * 8;
			data += 64 - pos;
			pos = 0;
		}
		if (len >= 64)
		{
			size_t blocks = len / 64;
			size_t bytes = blocks * 64;
			transfunc((void*)(data), blocks);
			len -= bytes;
			total += (bytes)* 8;
			data += bytes;
		}
		memcpy(&m[0]+pos, data, len);
		pos += len;
		total += len * 8;
	}

	void sha256::init()
	{
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;
		pos = 0;
		total = 0;
	};

	void sha256::transform(void* mp, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			uint32_t M[16];
			for (uint32_t i = 0; i < 64 / 4; i++)
			{
				M[i] = swap_uint32((reinterpret_cast<const uint32_t*>(mp)[blk * 16 + i]));
			}
#ifdef	CPPCRYPTO_DEBUG
			printf("M1 - M8: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
				M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

			uint32_t W[64];
			for (int t = 0; t <= 15; t++)
				W[t] = M[t];
			for (int t = 16; t <= 63; t++)
				W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

			uint32_t a = H[0];
			uint32_t b = H[1];
			uint32_t c = H[2];
			uint32_t d = H[3];
			uint32_t e = H[4];
			uint32_t f = H[5];
			uint32_t g = H[6];
			uint32_t h = H[7];

#ifdef	CPPCRYPTO_DEBUG
			printf("===============================================\n");
			printf("i = %d: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				-1, a, b, c, d, e, f, g, h);
#endif

			for (int t = 0; t <= 63; t++)
			{
				uint32_t T1 = h + sum1(e) + Ch(e, f, g) + SHA256_K[t] + W[t];
				uint32_t T2 = sum0(a) + Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
#ifdef	CPPCRYPTO_DEBUG
				printf("t = %d: %08X %08X %08X %08X %08X %08X %08X %08X (T1=%08X T2=%08X)\n",
					t, a, b, c, d, e, f, g, h, T1, T2);
#endif

			}
			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;
#ifdef	CPPCRYPTO_DEBUG
			printf("H[0] - H[7]: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
#endif
		}
	}

	void sha256::final(unsigned char* hash)
	{
		m[pos++] = 0x80;
		if (pos > 56)
		{
			memset(&m[0] + pos, 0, 64 - pos);
			transfunc(&m[0], 1);
			pos = 0;
		}
		memset(&m[0] + pos, 0, 56 - pos);
		uint64_t mlen = swap_uint64(total);
		memcpy(&m[0] + (64 - 8), &mlen, 64 / 8);
		transfunc(&m[0], 1);
		for (int i = 0; i < 8; i++)
		{
			H[i] = swap_uint32(H[i]);
		}
		memcpy(hash, H, 32);
	}


	void sha224::init()
	{
		H[0] = 0xc1059ed8;
		H[1] = 0x367cd507;
		H[2] = 0x3070dd17;
		H[3] = 0xf70e5939;
		H[4] = 0xffc00b31;
		H[5] = 0x68581511;
		H[6] = 0x64f98fa7;
		H[7] = 0xbefa4fa4;
		pos = 0;
		total = 0;
	};

	void sha256::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.data(), m.size() * sizeof(m[0]));
	}

}

