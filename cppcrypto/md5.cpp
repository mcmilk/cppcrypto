/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "md5.h"
#include "portability.h"
#include <memory.h>
//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	static const uint32_t K[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,	0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340,	0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,	0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa,	0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	static const unsigned char S[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,	4,
		11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};

	md5::~md5()
	{
		clear();
	}

	md5::md5()
	{
	}

	void md5::update(const unsigned char* data, size_t len)
	{
		if (pos && pos + len >= 64)
		{
			memcpy(&m[0] + pos, data, 64 - pos);
			transform(&m[0], 1);
			len -= 64 - pos;
			total += (64 - pos) * 8;
			data += 64 - pos;
			pos = 0;
		}
		if (len >= 64)
		{
			size_t blocks = len / 64;
			size_t bytes = blocks * 64;
			transform(data, blocks);
			len -= bytes;
			total += (bytes)* 8;
			data += bytes;
		}
		memcpy(&m[0] + pos, data, len);
		pos += len;
		total += len * 8;
	}

	void md5::init()
	{
		H[0] = 0x67452301;
		H[1] = 0xefcdab89;
		H[2] = 0x98badcfe;
		H[3] = 0x10325476;
		pos = 0;
		total = 0;
	};

	static inline void roundf(int round, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, const uint32_t* M)
	{
		a = b + rotatel32(a + (d ^ (b & (c ^ d))) + K[round] + M[round], S[round]);
	}

	static inline void roundg(int round, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, const uint32_t* M)
	{
		a = b + rotatel32(a + (c ^ (d & (b ^ c))) + K[round] + M[(5 * round + 1) % 16], S[round]);
	}

	static inline void roundh(int round, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, const uint32_t* M)
	{
		a = b + rotatel32(a + (b ^ c ^ d) + K[round] + M[(3 * round + 5) % 16], S[round]);
	}

	static inline void roundi(int round, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, const uint32_t* M)
	{
		a = b + rotatel32(a + (c ^ (b | ~d)) + K[round] + M[(7 * round) % 16], S[round]);
	}

	void md5::transform(const unsigned char* mp, uint64_t num_blks)
	{
		const uint32_t* M = (const uint32_t*)mp;
		for (uint64_t blk = 0; blk < num_blks; blk++, M += 16)
		{
			uint32_t a = H[0];
			uint32_t b = H[1];
			uint32_t c = H[2];
			uint32_t d = H[3];

			roundf(0, a, b, c, d, M);
			roundf(1, d, a, b, c, M);
			roundf(2, c, d, a, b, M);
			roundf(3, b, c, d, a, M);
			roundf(4, a, b, c, d, M);
			roundf(5, d, a, b, c, M);
			roundf(6, c, d, a, b, M);
			roundf(7, b, c, d, a, M);
			roundf(8, a, b, c, d, M);
			roundf(9, d, a, b, c, M);
			roundf(10, c, d, a, b, M);
			roundf(11, b, c, d, a, M);
			roundf(12, a, b, c, d, M);
			roundf(13, d, a, b, c, M);
			roundf(14, c, d, a, b, M);
			roundf(15, b, c, d, a, M);

			roundg(16, a, b, c, d, M);
			roundg(17, d, a, b, c, M);
			roundg(18, c, d, a, b, M);
			roundg(19, b, c, d, a, M);
			roundg(20, a, b, c, d, M);
			roundg(21, d, a, b, c, M);
			roundg(22, c, d, a, b, M);
			roundg(23, b, c, d, a, M);
			roundg(24, a, b, c, d, M);
			roundg(25, d, a, b, c, M);
			roundg(26, c, d, a, b, M);
			roundg(27, b, c, d, a, M);
			roundg(28, a, b, c, d, M);
			roundg(29, d, a, b, c, M);
			roundg(30, c, d, a, b, M);
			roundg(31, b, c, d, a, M);

			roundh(32, a, b, c, d, M);
			roundh(33, d, a, b, c, M);
			roundh(34, c, d, a, b, M);
			roundh(35, b, c, d, a, M);
			roundh(36, a, b, c, d, M);
			roundh(37, d, a, b, c, M);
			roundh(38, c, d, a, b, M);
			roundh(39, b, c, d, a, M);
			roundh(40, a, b, c, d, M);
			roundh(41, d, a, b, c, M);
			roundh(42, c, d, a, b, M);
			roundh(43, b, c, d, a, M);
			roundh(44, a, b, c, d, M);
			roundh(45, d, a, b, c, M);
			roundh(46, c, d, a, b, M);
			roundh(47, b, c, d, a, M);

			roundi(48, a, b, c, d, M);
			roundi(49, d, a, b, c, M);
			roundi(50, c, d, a, b, M);
			roundi(51, b, c, d, a, M);
			roundi(52, a, b, c, d, M);
			roundi(53, d, a, b, c, M);
			roundi(54, c, d, a, b, M);
			roundi(55, b, c, d, a, M);
			roundi(56, a, b, c, d, M);
			roundi(57, d, a, b, c, M);
			roundi(58, c, d, a, b, M);
			roundi(59, b, c, d, a, M);
			roundi(60, a, b, c, d, M);
			roundi(61, d, a, b, c, M);
			roundi(62, c, d, a, b, M);
			roundi(63, b, c, d, a, M);

			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
		}
	}

	void md5::final(unsigned char* hash)
	{
		m[pos++] = 0x80;
		if (pos > 56)
		{
			memset(&m[0] + pos, 0, 64 - pos);
			transform(&m[0], 1);
			pos = 0;
		}
		memset(&m[0] + pos, 0, 56 - pos);
		memcpy(&m[0] + (64 - 8), &total, 64 / 8);
		transform(&m[0], 1);
		memcpy(hash, H, 16);
	}

	void md5::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.data(), m.size() * sizeof(m[0]));
	}

}

