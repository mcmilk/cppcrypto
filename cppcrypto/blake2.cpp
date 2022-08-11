/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "portability.h"
#include "blake2.h"
#include <memory.h>
#include <functional>

//#define CPPCRYPTO_DEBUG
//#define NO_OPTIMIZED_VERSIONS

#ifdef _MSC_VER
#define inline __forceinline
#endif

extern "C"
{
	int blake2s_compress(uint32_t* ph, uint32_t* ptf, const unsigned char block[64]);
	int blake2b_compress(uint64_t* ph, const uint64_t* ptf, const unsigned char block[128]);
}

namespace cppcrypto
{
	static const uint32_t IV256[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	static const uint64_t IV512[8] = {
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
		0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
	};

	static const uint32_t S[12][16] = {
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
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
	};

	void blake2b::update(const unsigned char* data, size_t len)
	{
		while (pos + len > 128)
		{
			memcpy(m + pos, data, 128 - pos);
			len -= 128 - pos;
			total += 128 - pos;
			transfunc(false);
			data += 128 - pos;
			pos = 0;
		}
		memcpy(m + pos, data, len);
		pos += len;
		total += len;
	}

	void blake2b::init()
	{
		memcpy(H, IV512, 64);
		H[0] ^= 0x0000000001010000ULL;
		*((unsigned char*)H.get()) ^= hashsize()/8;
		pos = 0;
		total = 0;
	};

	static inline void G512(int r, int i, uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t* M)
	{
		a = a + b + M[S[r][2 * i]];
		d = rotater64(d ^ a, 32);
		c = c + d;
		b = rotater64(b ^ c, 24);
		a = a + b + M[S[r][2 * i + 1]];
		d = rotater64(d ^ a, 16);
		c = c + d;
		b = rotater64(b ^ c, 63);
	}

	static inline void round512(int r, uint64_t* M, uint64_t* v)
	{
		G512(r, 0, v[0], v[4], v[8], v[12], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15step1: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		G512(r, 1, v[1], v[5], v[9], v[13], M);
		G512(r, 2, v[2], v[6], v[10], v[14], M);
		G512(r, 3, v[3], v[7], v[11], v[15], M);
		G512(r, 4, v[0], v[5], v[10], v[15], M);
		G512(r, 5, v[1], v[6], v[11], v[12], M);
		G512(r, 6, v[2], v[7], v[8], v[13], M);
		G512(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}

	void blake2b::transform(bool padding)
	{
		uint64_t M[16];
		for (uint32_t i = 0; i < 128 / 8; i++)
		{
			M[i] = (reinterpret_cast<const uint64_t*>(m.get())[i]);
		}
#ifdef	CPPCRYPTO_DEBUG
		printf("M1 - M8: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint64_t t0 = total;
		uint64_t t1 = 0ULL;
		uint64_t f0 = 0ULL;
		uint64_t f1 = 0ULL;
		if (padding)
		{
			f0 = 0xFFFFFFFFFFFFFFFF;
			f1 = 0;
		}

#ifdef	CPPCRYPTO_DEBUG
		printf("t0: %016llx (%d), t1: %016llx\n", t0, t0, t1);
#endif

		uint64_t v[16];
		memcpy(v, H, sizeof(uint64_t) * 8);
		v[8 + 0] = IV512[0];
		v[8 + 1] = IV512[1];
		v[8 + 2] = IV512[2];
		v[8 + 3] = IV512[3];
		v[12] = t0 ^ IV512[4];
		v[13] = t1 ^ IV512[5];
		v[14] = f0 ^ IV512[6];
		v[15] = f1 ^ IV512[7];

#ifdef	CPPCRYPTO_DEBUG
		printf("v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		// The loop is fully unrolled for performance reasons
		round512(0, M, v);
		round512(1, M, v);
		round512(2, M, v);
		round512(3, M, v);
		round512(4, M, v);
		round512(5, M, v);
		round512(6, M, v);
		round512(7, M, v);
		round512(8, M, v);
		round512(9, M, v);
		round512(10, M, v);
		round512(11, M, v);

		H[0] = H[0] ^ v[0] ^ v[0 + 8];
		H[0 + 4] = H[0 + 4] ^ v[0 + 4] ^ v[0 + 8 + 4];
		H[1] = H[1] ^ v[1] ^ v[1 + 8];
		H[1 + 4] = H[1 + 4] ^ v[1 + 4] ^ v[1 + 8 + 4];
		H[2] = H[2] ^ v[2] ^ v[2 + 8];
		H[2 + 4] = H[2 + 4] ^ v[2 + 4] ^ v[2 + 8 + 4];
		H[3] = H[3] ^ v[3] ^ v[3 + 8];
		H[3 + 4] = H[3 + 4] ^ v[3 + 4] ^ v[3 + 8 + 4];

#ifdef	CPPCRYPTO_DEBUG
		printf("H[0] - H[7]: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
#endif
	}

	void blake2b::final(unsigned char* hash)
	{
		memset(m + pos, 0, 128 - pos);
		transfunc(true);
		memcpy(hash, H, hashsize() / 8);
	}


	blake2b::blake2b(size_t hashsize)
		: hs(hashsize)
	{
		validate_hash_size(hashsize, 512);
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse41())
			transfunc = [this](bool padding)
		{
			CPPCRYPTO_STATIC_ALIGN(32) uint64_t tf[4];
			tf[0] = static_cast<uint32_t>(total);
			tf[1] = 0;
			tf[2] = padding ? 0xFFFFFFFFFFFFFFFF : 0ULL;
			tf[3] = 0;

			blake2b_compress(H, tf, m);
		};
		//		else if (cpu_info::sse2())
		//			transfunc = [this](bool padding) { blake2s_512_compress_sse2(H, total, padding, m); };
		else
#endif
#ifdef NO_BIND_TO_FUNCTION
			transfunc = [this](bool padding) { transform(padding); };
#else
			transfunc = std::bind(&blake2b::transform, this, std::placeholders::_1);
#endif
	}

	blake2b::~blake2b()
	{
		clear();
	}

	void blake2b::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.get(), m.bytes());
	}


	void blake2s::update(const unsigned char* data, size_t len)
	{
		while (pos + len > 64)
		{
			memcpy(m + pos, data, 64 - pos);
			len -= 64 - pos;
			total += 64 - pos;
			transfunc(false);
			data += 64 - pos;
			pos = 0;
		}
		memcpy(m + pos, data, len);
		pos += len;
		total += len;
	}

	void blake2s::init()
	{
		memcpy(H, IV256, 32);
		H[0] ^= 0x01010000ULL;
		*((unsigned char*)H.get()) ^= hashsize() / 8;
		pos = 0;
		total = 0;
	};

	static inline void G256(int r, int i, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
	{
		a = a + b + M[S[r][2 * i]];
		d = rotater32(d ^ a, 16);
		c = c + d;
		b = rotater32(b ^ c, 12);
		a = a + b + M[S[r][2 * i + 1]];
		d = rotater32(d ^ a, 8);
		c = c + d;
		b = rotater32(b ^ c, 7);
	}

	static inline void round256(int r, uint32_t* M, uint32_t* v)
	{
		G256(r, 0, v[0], v[4], v[8], v[12], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15step1: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		G256(r, 1, v[1], v[5], v[9], v[13], M);
		G256(r, 2, v[2], v[6], v[10], v[14], M);
		G256(r, 3, v[3], v[7], v[11], v[15], M);
		G256(r, 4, v[0], v[5], v[10], v[15], M);
		G256(r, 5, v[1], v[6], v[11], v[12], M);
		G256(r, 6, v[2], v[7], v[8], v[13], M);
		G256(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}

	void blake2s::transform(bool padding)
	{
		uint32_t M[16];
		for (uint32_t i = 0; i < 64 / 4; i++)
		{
			M[i] = (reinterpret_cast<const uint32_t*>(m.get())[i]);
		}
#ifdef	CPPCRYPTO_DEBUG
		printf("M1 - M8: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint32_t t0 = static_cast<uint32_t>(total);
		uint32_t t1 = static_cast<uint32_t>((total) >> 32);
		uint32_t f0 = 0ULL;
		uint32_t f1 = 0ULL;
		if (padding)
		{
			f0 = 0xFFFFFFFF;
			f1 = 0;
		}

#ifdef	CPPCRYPTO_DEBUG
		printf("t0: %08x (%d), t1: %08x\n", t0, t0, t1);
#endif

		uint32_t v[16];
		memcpy(v, H, sizeof(uint32_t) * 8);
		v[8 + 0] = IV256[0];
		v[8 + 1] = IV256[1];
		v[8 + 2] = IV256[2];
		v[8 + 3] = IV256[3];
		v[12] = t0 ^ IV256[4];
		v[13] = t1 ^ IV256[5];
		v[14] = f0 ^ IV256[6];
		v[15] = f1 ^ IV256[7];

#ifdef	CPPCRYPTO_DEBUG
		printf("v0 - v15: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		// The loop is fully unrolled for performance reasons
		round256(0, M, v);
		round256(1, M, v);
		round256(2, M, v);
		round256(3, M, v);
		round256(4, M, v);
		round256(5, M, v);
		round256(6, M, v);
		round256(7, M, v);
		round256(8, M, v);
		round256(9, M, v);

		H[0] = H[0] ^ v[0] ^ v[0 + 8];
		H[0 + 4] = H[0 + 4] ^ v[0 + 4] ^ v[0 + 8 + 4];
		H[1] = H[1] ^ v[1] ^ v[1 + 8];
		H[1 + 4] = H[1 + 4] ^ v[1 + 4] ^ v[1 + 8 + 4];
		H[2] = H[2] ^ v[2] ^ v[2 + 8];
		H[2 + 4] = H[2 + 4] ^ v[2 + 4] ^ v[2 + 8 + 4];
		H[3] = H[3] ^ v[3] ^ v[3 + 8];
		H[3 + 4] = H[3 + 4] ^ v[3 + 4] ^ v[3 + 8 + 4];

#ifdef	CPPCRYPTO_DEBUG
		printf("H[0] - H[7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
			H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
#endif
	}

	void blake2s::final(unsigned char* hash)
	{
		memset(m + pos, 0, 64 - pos);
		transfunc(true);
		memcpy(hash, H, hashsize() / 8);
	}


	blake2s::blake2s(size_t hashsize)
		: hs(hashsize)
	{
		validate_hash_size(hashsize, 256);
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse41())
			transfunc = [this](bool padding)
			{
				CPPCRYPTO_STATIC_ALIGN(32) uint32_t tf[4];
				tf[0] = static_cast<uint32_t>(total);
				tf[1] = static_cast<uint32_t>((total) >> 32);
				tf[2] = padding ? 0xFFFFFFFF : 0ULL;
				tf[3] = 0;

				blake2s_compress(H, tf, m);
			};
		//		else if (cpu_info::sse2())
		//			transfunc = [this](bool padding) { blake2s_256_compress_sse2(H, total, padding, m); };
		else
#endif
#ifdef NO_BIND_TO_FUNCTION
		transfunc = [this](bool padding) { transform(padding); };
#else
		transfunc = std::bind(&blake2s::transform, this, std::placeholders::_1);
#endif
	}

	blake2s::~blake2s()
	{
		clear();
	}

	void blake2s::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.get(), m.bytes());
	}

}

