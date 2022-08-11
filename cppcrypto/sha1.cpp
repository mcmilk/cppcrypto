/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "sha1.h"
#include "portability.h"
#include <memory.h>
#include <functional>

//#define CPPCRYPTO_DEBUG
//#define NO_OPTIMIZED_VERSIONS

extern "C"
{
#ifdef _M_X64
	void sha1_update_intel(unsigned int *hash, void* input, size_t num_blocks);
#else
	void sha1_compress(uint32_t* state, const unsigned char* block);
#endif
}

namespace cppcrypto
{
	sha1::~sha1()
	{
		clear();
	}

	sha1::sha1()
	{
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef _M_X64
		if (cpu_info::ssse3())
#ifdef NO_BIND_TO_FUNCTION
			transfunc = [this](void* m, uint64_t num_blks) { sha1_update_intel(H.get(), m, num_blks); };
#else
			transfunc = std::bind(&sha1_update_intel, H.get(), std::placeholders::_1, std::placeholders::_2);
#endif
#else
		if (cpu_info::sse2())
			transfunc = [this](void* m, uint64_t num_blks)
		{
			for (uint64_t i = 0; i < num_blks; i++)
				sha1_compress(H, (unsigned char*)m + i * 64);
		};
#endif
		else
#endif
#ifdef NO_BIND_TO_FUNCTION
			transfunc = [this](void* m, uint64_t num_blks) { transform(m, num_blks); };
#else
			transfunc = std::bind(&sha1::transform, this, std::placeholders::_1, std::placeholders::_2);
#endif
	}

	static const uint32_t SHA1_K[] = {
		0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
	};

	static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (~x & z);
	}

	static inline uint32_t Parity(uint32_t x, uint32_t y, uint32_t z)
	{
		return x ^ y ^ z;
	}

	static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	void sha1::update(const unsigned char* data, size_t len)
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
		memcpy(&m[0] + pos, data, len);
		pos += len;
		total += len * 8;
	}

	void sha1::init()
	{
		H[0] = 0x67452301;
		H[1] = 0xefcdab89;
		H[2] = 0x98badcfe;
		H[3] = 0x10325476;
		H[4] = 0xc3d2e1f0;
		pos = 0;
		total = 0;
	};

	void sha1::transform(void* mp, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			uint32_t M[16];
			for (uint32_t i = 0; i < 64 / 4; i++)
			{
				M[i] = swap_uint32((reinterpret_cast<const uint32_t*>(mp)[blk * 16 + i]));
			}

			uint32_t W[80];
			for (int t = 0; t <= 15; t++)
				W[t] = M[t];
			for (int t = 16; t <= 79; t++)
				W[t] = rotatel32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

			uint32_t a = H[0];
			uint32_t b = H[1];
			uint32_t c = H[2];
			uint32_t d = H[3];
			uint32_t e = H[4];

			uint32_t K = SHA1_K[0];
			auto f = Ch;
			for (int t = 0; t <= 79; t++)
			{
				uint32_t T = rotatel32(a, 5) + f(b, c, d) + e + K + W[t];
				e = d;
				d = c;
				c = rotatel32(b, 30);
				b = a;
				a = T;

				if (t == 19)
				{
					f = Parity;
					K = SHA1_K[1];
				}
				else if (t == 39)
				{
					f = Maj;
					K = SHA1_K[2];
				}
				else if (t == 59)
				{
					f = Parity;
					K = SHA1_K[3];
				}

			}
			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
		}
	}

	void sha1::final(unsigned char* hash)
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
		for (int i = 0; i < 5; i++)
		{
			H[i] = swap_uint32(H[i]);
		}
		memcpy(hash, H, 160/8);
	}

	void sha1::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.data(), m.size() * sizeof(m[0]));
	}

}

