/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "cpuinfo.h"
#include "skein512.h"
#include <memory.h>

//#define DEBUG

#ifndef _MSC_VER
#define _aligned_malloc(a, b) aligned_alloc(b, a)
#define _aligned_free free

static inline uint64_t _rotl64(uint64_t x, unsigned n)
{
        return (x << n) | (x >> (64 - n));
}
#endif

#ifndef _M_X64
void Skein_512_Process_Block_mmx(uint64_t* T, uint64_t* X, const uint8_t *blkPtr, size_t blkCnt, size_t byteCntAdd);
#endif

namespace cppcrypto
{

	void skein512_512::update(const uint8_t* data, size_t len)
	{
		if (pos && pos + len > 64)
		{
			memcpy(m + pos, data, 64 - pos);
			transfunc(m, 1, 64);
			len -= 64 - pos;
			total += 64 - pos;
			data += 64 - pos;
			pos = 0;
		}
		if (len > 64)
		{
			size_t blocks = (len - 1) / 64;
			size_t bytes = blocks * 64;
			transfunc((void*)(data), blocks, 64);
			len -= bytes;
			total += (bytes)* 8;
			data += bytes;
		}
		memcpy(m+pos, data, len);
		pos += len;
		total += len * 8;
	}

	void skein512_512::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0x4903ADFF749C51CE;
		H[1] = 0x0D95DE399746DF03;
		H[2] = 0x8FD1934127C79BCE;
		H[3] = 0x9A255629FF352CB1;
		H[4] = 0x5DB62599DF6CA7B0;
		H[5] = 0xEABE394CA9D5C3F4;
		H[6] = 0x991112C71A75B523;
		H[7] = 0xAE18A40B660FCC33;

		pos = 0;
		total = 0;
	};

#define G(G0, G1, G2, G3, G4, G5, G6, G7, C0, C1, C2, C3) \
	G0 += G1; \
	G1 = _rotl64(G1, C0) ^ G0; \
	G2 += G3; \
	G3 = _rotl64(G3, C1) ^ G2; \
	G4 += G5; \
	G5 = _rotl64(G5, C2) ^ G4; \
	G6 += G7; \
	G7 = _rotl64(G7, C3) ^ G6;

#define KS(r) \
	G0 += keys[(r + 1) % 9]; \
	G1 += keys[(r + 2) % 9]; \
	G2 += keys[(r + 3) % 9]; \
	G3 += keys[(r + 4) % 9]; \
	G4 += keys[(r + 5) % 9]; \
	G5 += keys[(r + 6) % 9] + tweaks[(r + 1) % 3]; \
	G6 += keys[(r + 7) % 9] + tweaks[(r + 2) % 3]; \
	G7 += keys[(r + 8) % 9] + r + 1;

#define G8(r) \
	G(G0, G1, G2, G3, G4, G5, G6, G7, 46, 36, 19, 37); \
	G(G2, G1, G4, G7, G6, G5, G0, G3, 33, 27, 14, 42); \
	G(G4, G1, G6, G3, G0, G5, G2, G7, 17, 49, 36, 39); \
	G(G6, G1, G0, G7, G2, G5, G4, G3, 44, 9, 54, 56); \
	KS(r) \
    G(G0, G1, G2, G3, G4, G5, G6, G7, 39, 30, 34, 24); \
	G(G2, G1, G4, G7, G6, G5, G0, G3, 13, 50, 10, 17); \
	G(G4, G1, G6, G3, G0, G5, G2, G7, 25, 29, 39, 43); \
	G(G6, G1, G0, G7, G2, G5, G4, G3, 8, 35, 56, 22); \
	KS(r + 1)

	void skein512_512::transform(void* m, uint64_t num_blks, size_t reallen)
	{
		uint64_t keys[9];
		uint64_t tweaks[3];

		for (uint64_t b = 0; b < num_blks; b++)
		{
			uint64_t M[8];
			uint64_t G0,G1,G2,G3,G4,G5,G6,G7;
			for (uint64_t i = 0; i < 64 / 8; i++)
			{
				M[i] = (reinterpret_cast<const uint64_t*>(m)[b * 8 + i]);
			}

			memcpy(keys, H, sizeof(uint64_t)*8);
			memcpy(tweaks, tweak, sizeof(uint64_t)*2);
			tweaks[0] += reallen;
			tweaks[2] = tweaks[0] ^ tweaks[1];
			keys[8] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3] ^ keys[4] ^ keys[5] ^ keys[6] ^ keys[7];

			G0 = M[0] + keys[0];
			G1 = M[1] + keys[1];
			G2 = M[2] + keys[2];
			G3 = M[3] + keys[3];
			G4 = M[4] + keys[4];
			G5 = M[5] + keys[5];
			G6 = M[6] + keys[6];
			G7 = M[7] + keys[7];
			G5 += tweaks[0];
			G6 += tweaks[1];

			// The loop is fully unrolled for performance reasons
			G8(0);
			G8(2);
			G8(4);
			G8(6);
			G8(8);
			G8(10);
			G8(12);
			G8(14);
			G8(16);

			tweaks[1] &= ~(64ULL << 56);
			tweak[0] = tweaks[0];
			tweak[1] = tweaks[1];
			H[0] = G0 ^ M[0];
			H[1] = G1 ^ M[1];
			H[2] = G2 ^ M[2];
			H[3] = G3 ^ M[3];
			H[4] = G4 ^ M[4];
			H[5] = G5 ^ M[5];
			H[6] = G6 ^ M[6];
			H[7] = G7 ^ M[7];
		}

	}

	void skein512_512::final(uint8_t* hash)
	{
		tweak[1] |= 1ULL << 63; // last block
		if (pos < 64)
			memset(m + pos, 0, 64 - pos);

		transfunc(m, 1, pos);

		// generate output
		tweak[0] = 0;
		tweak[1] = 255ULL << 56;
		memset(m, 0, 64);
		transfunc(m, 1, 8);

		memcpy(hash, H, hashsize() / 8);
	}


	void skein512_256::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0xCCD044A12FDB3E13;
		H[1] = 0xE83590301A79A9EB;
		H[2] = 0x55AEA0614F816E6F;
		H[3] = 0x2A2767A4AE9B94DB;
		H[4] = 0xEC06025E74DD7683;
		H[5] = 0xE7A436CDC4746251;
		H[6] = 0xC36FBAF9393AD185;
		H[7] = 0x3EEDBA1833EDFC13;

		pos = 0;
		total = 0;
	};


	void skein512_384::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0xA3F6C6BF3A75EF5F;
		H[1] = 0xB0FEF9CCFD84FAA4;
		H[2] = 0x9D77DD663D770CFE;
		H[3] = 0xD798CBF3B468FDDA;
		H[4] = 0x1BC4A6668A0E4465;
		H[5] = 0x7ED7D434E5807407;
		H[6] = 0x548FC1ACD4EC44D6;
		H[7] = 0x266E17546AA18FF8;

		pos = 0;
		total = 0;
	};

	void skein512_224::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0xCCD0616248677224;
		H[1] = 0xCBA65CF3A92339EF;
		H[2] = 0x8CCD69D652FF4B64;
		H[3] = 0x398AED7B3AB890B4;
		H[4] = 0x0F59D1B1457D2BD0;
		H[5] = 0x6776FE6575D4EB3D;
		H[6] = 0x99FBC70E997413E9;
		H[7] = 0x9E2CFCCFE1C41EF7;

		pos = 0;
		total = 0;
	};

	void skein512_128::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0xA8BC7BF36FBF9F52;
		H[1] = 0x1E9872CEBD1AF0AA;
		H[2] = 0x309B1790B32190D3;
		H[3] = 0xBCFBB8543F94805C;
		H[4] = 0x0DA61BCD6E31B11B;
		H[5] = 0x1A18EBEAD46A32E3;
		H[6] = 0xA2CC5B18CE84AA82;
		H[7] = 0x6982AB289D46982D;

		pos = 0;
		total = 0;
	};

	void skein512_160::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0x28B81A2AE013BD91;
		H[1] = 0xC2F11668B5BDF78F;
		H[2] = 0x1760D8F3F6A56F12;
		H[3] = 0x4FB747588239904F;
		H[4] = 0x21EDE07F7EAF5056;
		H[5] = 0xD908922E63ED70B8;
		H[6] = 0xB8EC76FFECCB52FA;
		H[7] = 0x01A47BB8A3F27A6E;

		pos = 0;
		total = 0;
	};

	skein512_512::skein512_512()
	{
		H = (uint64_t*)_aligned_malloc(sizeof(uint64_t) * 8, 32);
#ifndef _M_X64
		if (cpu_info::mmx())
			transfunc = [this](void* m, uint64_t num_blks, size_t reallen) { Skein_512_Process_Block_mmx(tweak, H, (uint8_t*)m, static_cast<size_t>(num_blks), reallen); };
		else
#endif
			transfunc = bind(&skein512_512::transform, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

	}

	skein512_512::~skein512_512()
	{
		_aligned_free(H);
	}

}
