/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include <malloc.h>
#include "cpuinfo.h"
#include "sha3.h"
#include <memory.h>

#ifndef _MSC_VER
static inline uint64_t _rotl64(uint64_t x, unsigned n)
{
        return (x << n) | (x >> (64 - n));
}
#else
#define inline __forceinline
#endif


namespace cppcrypto
{
	static const uint64_t RC[24] =
	{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

	void sha3_512::init()
	{
		if (impl_)
			return impl_->init(576, 1024);
		memset(A, 0, sizeof(A));
		pos = 0;
	}

	void sha3_512::update(const uint8_t* data, size_t len)
	{
		if (impl_)
			return impl_->update(data, len);
		if (pos && pos + len >= 72)
		{
			memcpy(m + pos, data, 72 - pos);
			transform(m, 1);
			len -= 72 - pos;
			data += 72 - pos;
			pos = 0;
		}
		if (len >= 72)
		{
			size_t blocks = len / 72;
			size_t bytes = blocks * 72;
			transform((void*)data, blocks);
			len -= bytes;
			data += bytes;
		}
		memcpy(m + pos, data, len);
		pos += len;
	}

	static inline void dotransform(uint64_t* A)
	{
		for (int round = 0; round < 24; round++)
		{
			uint64_t C[5], D[5];
			C[0] = A[0 * 5 + 0] ^ A[1 * 5 + 0] ^ A[2 * 5 + 0] ^ A[3 * 5 + 0] ^ A[4 * 5 + 0];
			C[1] = A[0 * 5 + 1] ^ A[1 * 5 + 1] ^ A[2 * 5 + 1] ^ A[3 * 5 + 1] ^ A[4 * 5 + 1];
			C[2] = A[0 * 5 + 2] ^ A[1 * 5 + 2] ^ A[2 * 5 + 2] ^ A[3 * 5 + 2] ^ A[4 * 5 + 2];
			C[3] = A[0 * 5 + 3] ^ A[1 * 5 + 3] ^ A[2 * 5 + 3] ^ A[3 * 5 + 3] ^ A[4 * 5 + 3];
			C[4] = A[0 * 5 + 4] ^ A[1 * 5 + 4] ^ A[2 * 5 + 4] ^ A[3 * 5 + 4] ^ A[4 * 5 + 4];

			D[0] = C[4] ^ _rotl64(C[1], 1);
			D[1] = C[0] ^ _rotl64(C[2], 1);
			D[2] = C[1] ^ _rotl64(C[3], 1);
			D[3] = C[2] ^ _rotl64(C[4], 1);
			D[4] = C[3] ^ _rotl64(C[0], 1);

			uint64_t B0 = A[0 * 5 + 0] ^ D[0];
			uint64_t B10 = _rotl64(A[0 * 5 + 1] ^ D[1], 1);
			uint64_t B20 = _rotl64(A[0 * 5 + 2] ^ D[2], 62);
			uint64_t B5 = _rotl64(A[0 * 5 + 3] ^ D[3], 28);
			uint64_t B15 = _rotl64(A[0 * 5 + 4] ^ D[4], 27);

			uint64_t B16 = _rotl64(A[1 * 5 + 0] ^ D[0], 36);
			uint64_t B1 = _rotl64(A[1 * 5 + 1] ^ D[1], 44);
			uint64_t B11 = _rotl64(A[1 * 5 + 2] ^ D[2], 6);
			uint64_t B21 = _rotl64(A[1 * 5 + 3] ^ D[3], 55);
			uint64_t B6 = _rotl64(A[1 * 5 + 4] ^ D[4], 20);

			uint64_t B7 = _rotl64(A[2 * 5 + 0] ^ D[0], 3);
			uint64_t B17 = _rotl64(A[2 * 5 + 1] ^ D[1], 10);
			uint64_t B2 = _rotl64(A[2 * 5 + 2] ^ D[2], 43);
			uint64_t B12 = _rotl64(A[2 * 5 + 3] ^ D[3], 25);
			uint64_t B22 = _rotl64(A[2 * 5 + 4] ^ D[4], 39);

			uint64_t B23 = _rotl64(A[3 * 5 + 0] ^ D[0], 41);
			uint64_t B8 = _rotl64(A[3 * 5 + 1] ^ D[1], 45);
			uint64_t B18 = _rotl64(A[3 * 5 + 2] ^ D[2], 15);
			uint64_t B3 = _rotl64(A[3 * 5 + 3] ^ D[3], 21);
			uint64_t B13 = _rotl64(A[3 * 5 + 4] ^ D[4], 8);

			uint64_t B14 = _rotl64(A[4 * 5 + 0] ^ D[0], 18);
			uint64_t B24 = _rotl64(A[4 * 5 + 1] ^ D[1], 2);
			uint64_t B9 = _rotl64(A[4 * 5 + 2] ^ D[2], 61);
			uint64_t B19 = _rotl64(A[4 * 5 + 3] ^ D[3], 56);
			uint64_t B4 = _rotl64(A[4 * 5 + 4] ^ D[4], 14);

			A[0 * 5 + 0] = B0 ^ ((~B1) & B2);
			A[0 * 5 + 1] = B1 ^ ((~B2) & B3);
			A[0 * 5 + 2] = B2 ^ ((~B3) & B4);
			A[0 * 5 + 3] = B3 ^ ((~B4) & B0);
			A[0 * 5 + 4] = B4 ^ ((~B0) & B1);

			A[1 * 5 + 0] = B5 ^ ((~B6) & B7);
			A[1 * 5 + 1] = B6 ^ ((~B7) & B8);
			A[1 * 5 + 2] = B7 ^ ((~B8) & B9);
			A[1 * 5 + 3] = B8 ^ ((~B9) & B5);
			A[1 * 5 + 4] = B9 ^ ((~B5) & B6);

			A[2 * 5 + 0] = B10 ^ ((~B11) & B12);
			A[2 * 5 + 1] = B11 ^ ((~B12) & B13);
			A[2 * 5 + 2] = B12 ^ ((~B13) & B14);
			A[2 * 5 + 3] = B13 ^ ((~B14) & B10);
			A[2 * 5 + 4] = B14 ^ ((~B10) & B11);

			A[3 * 5 + 0] = B15 ^ ((~B16) & B17);
			A[3 * 5 + 1] = B16 ^ ((~B17) & B18);
			A[3 * 5 + 2] = B17 ^ ((~B18) & B19);
			A[3 * 5 + 3] = B18 ^ ((~B19) & B15);
			A[3 * 5 + 4] = B19 ^ ((~B15) & B16);

			A[4 * 5 + 0] = B20 ^ ((~B21) & B22);
			A[4 * 5 + 1] = B21 ^ ((~B22) & B23);
			A[4 * 5 + 2] = B22 ^ ((~B23) & B24);
			A[4 * 5 + 3] = B23 ^ ((~B24) & B20);
			A[4 * 5 + 4] = B24 ^ ((~B20) & B21);

			A[0] ^= RC[round];
		}
	}

	void sha3_512::transform(void* m, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			for (int i = 0; i < 9; i++)
				A[i] ^= reinterpret_cast<const uint64_t*>((char*)m+blk*72)[i];

			dotransform(A);
		}
	}

	void sha3_512::final(uint8_t* hash)
	{
		if (impl_)
			return impl_->final(hash, 512);
		m[pos++] = 0x06;
		memset(m + pos, 0, 72 - pos);
		m[71] |= 0x80;
		transform(m, 1);
		memcpy(hash, A, hashsize() / 8);
	}

	void sha3_256::init()
	{
		if (impl_)
			return impl_->init(1088, 512);
		memset(A, 0, sizeof(A));
		pos = 0;
	}

	void sha3_256::update(const uint8_t* data, size_t len)
	{
		if (impl_)
			return impl_->update(data, len);
		if (pos && pos + len >= 136)
		{
			memcpy(m + pos, data, 136 - pos);
			transform(m, 1);
			len -= 136 - pos;
			data += 136 - pos;
			pos = 0;
		}
		if (len >= 136)
		{
			size_t blocks = len / 136;
			size_t bytes = blocks * 136;
			transform((void*)data, blocks);
			len -= bytes;
			data += bytes;
		}
		memcpy(m + pos, data, len);
		pos += len;
	}

	void sha3_256::transform(void* m, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			for (int i = 0; i < 17; i++)
				A[i] ^= reinterpret_cast<const uint64_t*>((char*)m + blk * 136)[i];

			dotransform(A);
		}
	}

	void sha3_256::final(uint8_t* hash)
	{
		if (impl_)
			return impl_->final(hash, 256);
		m[pos++] = 0x06;
		memset(m + pos, 0, 136 - pos);
		m[135] |= 0x80;
		transform(m, 1);
		memcpy(hash, A, hashsize() / 8);
	}

	void sha3_384::init()
	{
		if (impl_)
			return impl_->init(832, 768);
		memset(A, 0, sizeof(A));
		pos = 0;
	}

	void sha3_384::update(const uint8_t* data, size_t len)
	{
		if (impl_)
			return impl_->update(data, len);
		if (pos && pos + len >= 104)
		{
			memcpy(m + pos, data, 104 - pos);
			transform(m, 1);
			len -= 104 - pos;
			data += 104 - pos;
			pos = 0;
		}
		if (len >= 104)
		{
			size_t blocks = len / 104;
			size_t bytes = blocks * 104;
			transform((void*)data, blocks);
			len -= bytes;
			data += bytes;
		}
		memcpy(m + pos, data, len);
		pos += len;
	}

	void sha3_384::transform(void* m, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			for (int i = 0; i < 13; i++)
				A[i] ^= reinterpret_cast<const uint64_t*>((char*)m + blk * 104)[i];

			dotransform(A);
		}
	}

	void sha3_384::final(uint8_t* hash)
	{
		if (impl_)
			return impl_->final(hash, 384);
		m[pos++] = 0x06;
		memset(m + pos, 0, 104 - pos);
		m[103] |= 0x80;
		transform(m, 1);
		memcpy(hash, A, hashsize() / 8);
	}

	void sha3_224::init()
	{
		if (impl_)
			return impl_->init(1152, 448);
		memset(A, 0, sizeof(A));
		pos = 0;
	}

	void sha3_224::update(const uint8_t* data, size_t len)
	{
		if (impl_)
			return impl_->update(data, len);
		if (pos && pos + len >= 144)
		{
			memcpy(m + pos, data, 144 - pos);
			transform(m, 1);
			len -= 144 - pos;
			data += 144 - pos;
			pos = 0;
		}
		if (len >= 144)
		{
			size_t blocks = len / 144;
			size_t bytes = blocks * 144;
			transform((void*)data, blocks);
			len -= bytes;
			data += bytes;
		}
		memcpy(m + pos, data, len);
		pos += len;
	}

	void sha3_224::transform(void* m, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			for (int i = 0; i < 18; i++)
				A[i] ^= reinterpret_cast<const uint64_t*>((char*)m + blk * 144)[i];

			dotransform(A);
		}
	}

	void sha3_224::final(uint8_t* hash)
	{
		if (impl_)
			return impl_->final(hash, 224);
		m[pos++] = 0x06;
		memset(m + pos, 0, 144 - pos);
		m[143] |= 0x80;
		transform(m, 1);
		memcpy(hash, A, hashsize() / 8);
	}

	sha3_512::sha3_512()
		: impl_(0)
	{
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::ssse3())
			impl_ = new detail::sha3_impl_ssse3;
#endif
	}
	sha3_512::~sha3_512()
	{
		delete impl_;
	}
	sha3_256::sha3_256()
		: impl_(0)
	{
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::ssse3())
			impl_ = new detail::sha3_impl_ssse3;
#endif
	}
	sha3_256::~sha3_256()
	{
		delete impl_;
	}
	sha3_384::sha3_384()
		: impl_(0)
	{
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::ssse3())
			impl_ = new detail::sha3_impl_ssse3;
#endif
	}
	sha3_384::~sha3_384()
	{
		delete impl_;
	}
	sha3_224::sha3_224()
		: impl_(0)
	{
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::ssse3())
			impl_ = new detail::sha3_impl_ssse3;
#endif
	}
	sha3_224::~sha3_224()
	{
		delete impl_;
	}

}
