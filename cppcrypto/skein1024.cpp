/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "skein1024.h"
#include "portability.h"
#include <memory.h>
#include <functional>
#include <algorithm>

#if defined(_MSC_VER) && defined(_M_X64)
#include <immintrin.h>
#endif
//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{

void skein1024::update(const unsigned char* data, size_t len)
{
	if (pos && pos + len > 128)
	{
		memcpy(m + pos, data, 128 - pos);
		transfunc(m, 1, 128);
		len -= 128 - pos;
		total += 128 - pos;
		data += 128 - pos;
		pos = 0;
	}
	if (len > 128)
	{
		size_t blocks = (len - 1) / 128;
		size_t bytes = blocks * 128;
		transfunc((void*)(data), blocks, 128);
		len -= bytes;
		total += (bytes)* 8;
		data += bytes;
	}
	memcpy(m+pos, data, len);
	pos += len;
	total += len * 8;
}

#define G(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, C1, C2, C3, C4, C5, C6, C7, C8) \
	G0 += G1; \
	G1 = rotatel64(G1, C1) ^ G0; \
	G2 += G3; \
	G3 = rotatel64(G3, C2) ^ G2; \
	G4 += G5; \
	G5 = rotatel64(G5, C3) ^ G4; \
	G6 += G7; \
	G7 = rotatel64(G7, C4) ^ G6; \
	G8 += G9; \
	G9 = rotatel64(G9, C5) ^ G8; \
	G10 += G11; \
	G11 = rotatel64(G11, C6) ^ G10; \
	G12 += G13; \
	G13 = rotatel64(G13, C7) ^ G12; \
	G14 += G15; \
	G15 = rotatel64(G15, C8) ^ G14;

#define KS(r) \
	G0 += keys[(r + 1) % 17]; \
	G1 += keys[(r + 2) % 17]; \
	G2 += keys[(r + 3) % 17]; \
	G3 += keys[(r + 4) % 17]; \
	G4 += keys[(r + 5) % 17]; \
	G5 += keys[(r + 6) % 17]; \
	G6 += keys[(r + 7) % 17]; \
	G7 += keys[(r + 8) % 17]; \
	G8 += keys[(r + 9) % 17]; \
	G9 += keys[(r + 10) % 17]; \
	G10 += keys[(r + 11) % 17]; \
	G11 += keys[(r + 12) % 17]; \
	G12 += keys[(r + 13) % 17]; \
	G13 += keys[(r + 14) % 17] + tweaks[(r + 1) % 3]; \
	G14 += keys[(r + 15) % 17] + tweaks[(r + 2) % 3]; \
	G15 += keys[(r + 16) % 17] + r + 1;

#define G8(r) \
	G(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 24, 13, 8, 47, 8, 17, 22, 37); \
	G(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 38, 19, 10, 55, 49, 18, 23, 52); \
	G(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 33, 4, 51, 13, 34, 41, 59, 17); \
	G(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 5, 20, 48, 41, 47, 28, 16, 25); \
	KS(r); \
	G(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 41, 9, 37, 31, 12, 47, 44, 30); \
	G(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 16, 34, 56, 51, 4, 53, 42, 41); \
	G(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 31, 44, 47, 46, 19, 42, 44, 25); \
	G(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 9, 48, 35, 52, 23, 31, 37, 20); \
	KS(r + 1);

#define GRORX(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, C1, C2, C3, C4, C5, C6, C7, C8) \
	G0 += G1; \
	G1 = _rorx_u64(G1, 64-C1) ^ G0; \
	G2 += G3; \
	G3 = _rorx_u64(G3, 64-C2) ^ G2; \
	G4 += G5; \
	G5 = _rorx_u64(G5, 64-C3) ^ G4; \
	G6 += G7; \
	G7 = _rorx_u64(G7, 64-C4) ^ G6; \
	G8 += G9; \
	G9 = _rorx_u64(G9, 64-C5) ^ G8; \
	G10 += G11; \
	G11 = _rorx_u64(G11, 64-C6) ^ G10; \
	G12 += G13; \
	G13 = _rorx_u64(G13, 64-C7) ^ G12; \
	G14 += G15; \
	G15 = _rorx_u64(G15, 64-C8) ^ G14;

#define G8RORX(r) \
	GRORX(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 24, 13, 8, 47, 8, 17, 22, 37); \
	GRORX(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 38, 19, 10, 55, 49, 18, 23, 52); \
	GRORX(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 33, 4, 51, 13, 34, 41, 59, 17); \
	GRORX(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 5, 20, 48, 41, 47, 28, 16, 25); \
	KS(r); \
	GRORX(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 41, 9, 37, 31, 12, 47, 44, 30); \
	GRORX(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 16, 34, 56, 51, 4, 53, 42, 41); \
	GRORX(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 31, 44, 47, 46, 19, 42, 44, 25); \
	GRORX(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 9, 48, 35, 52, 23, 31, 37, 20); \
	KS(r + 1);


// The loop is fully unrolled for performance reasons
#define XOR2H() \
	H[0] = G0 ^ M[0]; \
	H[1] = G1 ^ M[1]; \
	H[2] = G2 ^ M[2]; \
	H[3] = G3 ^ M[3]; \
	H[4] = G4 ^ M[4]; \
	H[5] = G5 ^ M[5]; \
	H[6] = G6 ^ M[6]; \
	H[7] = G7 ^ M[7]; \
	H[8] = G8 ^ M[8]; \
	H[9] = G9 ^ M[9]; \
	H[10] = G10 ^ M[10]; \
	H[11] = G11 ^ M[11]; \
	H[12] = G12 ^ M[12]; \
	H[13] = G13 ^ M[13]; \
	H[14] = G14 ^ M[14]; \
	H[15] = G15 ^ M[15];

#define ADD2G() \
	G0 = M[0] + keys[0]; \
	G1 = M[1] + keys[1]; \
	G2 = M[2] + keys[2]; \
	G3 = M[3] + keys[3]; \
	G4 = M[4] + keys[4]; \
	G5 = M[5] + keys[5]; \
	G6 = M[6] + keys[6]; \
	G7 = M[7] + keys[7]; \
	G8 = M[8] + keys[8]; \
	G9 = M[9] + keys[9]; \
	G10 = M[10] + keys[10]; \
	G11 = M[11] + keys[11]; \
	G12 = M[12] + keys[12]; \
	G13 = M[13] + keys[13]; \
	G14 = M[14] + keys[14]; \
	G15 = M[15] + keys[15]; \
	G13 += tweaks[0]; \
	G14 += tweaks[1];

#define SETUPG() \
	uint64_t M[16]; \
	uint64_t G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15; \
	for (uint64_t i = 0; i < 128 / 8; i++) \
	{ \
		M[i] = (reinterpret_cast<const uint64_t*>(mp)[b * 16 + i]); \
	} \
	memcpy(keys, H, sizeof(uint64_t) * 16); \
	memcpy(tweaks, tweak, sizeof(uint64_t) * 2); \
	tweaks[0] += reallen; \
	tweaks[2] = tweaks[0] ^ tweaks[1]; \
	keys[16] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3] ^ keys[4] ^ keys[5] ^ keys[6] ^ keys[7] \
		^ keys[8] ^ keys[9] ^ keys[10] ^ keys[11] ^ keys[12] ^ keys[13] ^ keys[14] ^ keys[15];

#if defined(_MSC_VER) && defined(_M_X64)
void skein1024::transform_rorx(void* mp, uint64_t num_blks, size_t reallen)
{
	uint64_t keys[17];
	uint64_t tweaks[3];

	for (uint64_t b = 0; b < num_blks; b++)
	{
		SETUPG();
		ADD2G();

		// The loop is fully unrolled for performance reasons
		G8RORX(0); G8RORX(2); G8RORX(4); G8RORX(6); G8RORX(8); G8RORX(10); G8RORX(12); G8RORX(14); G8RORX(16); G8RORX(18);

		tweaks[1] &= ~(64ULL << 56);
		tweak[0] = tweaks[0];
		tweak[1] = tweaks[1];

		XOR2H()
	}
}
#endif

void skein1024::transform(void* mp, uint64_t num_blks, size_t reallen)
{
	uint64_t keys[17];
	uint64_t tweaks[3];

	for (uint64_t b = 0; b < num_blks; b++)
	{
		SETUPG();
		ADD2G();

		// The loop is fully unrolled for performance reasons
		G8(0); G8(2); G8(4); G8(6); G8(8); G8(10); G8(12); G8(14); G8(16); G8(18);

		tweaks[1] &= ~(64ULL << 56);
		tweak[0] = tweaks[0];
		tweak[1] = tweaks[1];

		XOR2H()
	}

}

void skein1024::init()
{
	tweak[0] = 0ULL;
	tweak[1] = (1ULL << 62) | (4ULL << 56) | (1ULL << 63);
	pos = 0;
	total = 0;

	switch(hs)
	{
		case 1024:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xD593DA0741E72355;
			H[1] = 0x15B5E511AC73E00C;
			H[2] = 0x5180E5AEBAF2C4F0;
			H[3] = 0x03BD41D3FCBCAFAF;
			H[4] = 0x1CAEC6FD1983A898;
			H[5] = 0x6E510B8BCDD0589F;
			H[6] = 0x77E2BDFDC6394ADA;
			H[7] = 0xC11E1DB524DCB0A3;
			H[8] = 0xD6D14AF9C6329AB5;
			H[9] = 0x6A9B0BFC6EB67E0D;
			H[10] = 0x9243C60DCCFF1332;
			H[11] = 0x1A1F1DDE743F02D4;
			H[12] = 0x0996753C10ED0BB8;
			H[13] = 0x6572DD22F2B4969A;
			H[14] = 0x61FD3062D00A579A;
			H[15] = 0x1DE0536E8682E539;
			return;
		case 512:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xCAEC0E5D7C1B1B18;
			H[1] = 0xA01B0E045F03E802;
			H[2] = 0x33840451ED912885;
			H[3] = 0x374AFB04EAEC2E1C;
			H[4] = 0xDF25A0E2813581F7;
			H[5] = 0xE40040938B12F9D2;
			H[6] = 0xA662D539C2ED39B6;
			H[7] = 0xFA8B85CF45D8C75A;
			H[8] = 0x8316ED8E29EDE796;
			H[9] = 0x053289C02E9F91B8;
			H[10] = 0xC3F8EF1D6D518B73;
			H[11] = 0xBDCEC3C4D5EF332E;
			H[12] = 0x549A7E5222974487;
			H[13] = 0x670708725B749816;
			H[14] = 0xB9CD28FBF0581BD1;
			H[15] = 0x0E2940B815804974;
			return;
		case 384:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0x5102B6B8C1894A35;
			H[1] = 0xFEEBC9E3FE8AF11A;
			H[2] = 0x0C807F06E32BED71;
			H[3] = 0x60C13A52B41A91F6;
			H[4] = 0x9716D35DD4917C38;
			H[5] = 0xE780DF126FD31D3A;
			H[6] = 0x797846B6C898303A;
			H[7] = 0xB172C2A8B3572A3B;
			H[8] = 0xC9BC8203A6104A6C;
			H[9] = 0x65909338D75624F4;
			H[10] = 0x94BCC5684B3F81A0;
			H[11] = 0x3EBBF51E10ECFD46;
			H[12] = 0x2DF50F0BEEB08542;
			H[13] = 0x3B5A65300DBC6516;
			H[14] = 0x484B9CD2167BBCE1;
			H[15] = 0x2D136947D4CBAFEA;
			return;
		case 256:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xC34E298E25163A31;
			H[1] = 0x42EDCD85DE005624;
			H[2] = 0x4674977287B7EF4F;
			H[3] = 0x87BBDA95FE4D6093;
			H[4] = 0x0C095E03006177E0;
			H[5] = 0xFE08C456A974A0C9;
			H[6] = 0xF69D992870F8B94B;
			H[7] = 0x39FDE39337D5A96B;
			H[8] = 0xBB7E755ED6AF84E0;
			H[9] = 0x1B11521AC224584F;
			H[10] = 0x81D24A0DC41F4773;
			H[11] = 0x35C49CCDC82EB77A;
			H[12] = 0xFC0192D9F180D6E8;
			H[13] = 0x0DE61DBFC2C37FE3;
			H[14] = 0x77C47FA89F60E8F2;
			H[15] = 0x7C2D2F4DB209702B;
			return;
	}

	memset(H, 0, h.bytes());
	memset(m, 0, sizeof(m));
	m[0] = 0x53;
	m[1] = 0x48;
	m[2] = 0x41;
	m[3] = 0x33;
	m[4] = 0x01;
	uint64_t size64 = hs;
	memcpy(m + 8, &size64, 8);

#ifdef	CPPCRYPTO_DEBUG
	for (int i = 0; i < sizeof(m); i++)
		printf("%02x", m[i]);
#endif

	transfunc(m, 1, 32);

#ifdef	CPPCRYPTO_DEBUG
	printf("H0 - H15: %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X %016I64X\n",
		H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8], H[9], H[10], H[11], H[12], H[13], H[14], H[15]);
#endif

	pos = 0;
	total = 0;
	tweak[0] = 0ULL;
	tweak[1] = (1ULL << 62) | (48ULL << 56);
}

void skein1024::final(unsigned char* hash)
{
	tweak[1] |= 1ULL << 63; // last block
	if (pos < 128)
		memset(m + pos, 0, 128 - pos);

	transfunc(m, 1, pos);

	// generate output
	memset(m, 0, 128);
	if (hs <= 1024)
	{
		tweak[0] = 0;
		tweak[1] = 255ULL << 56;
		transfunc(m, 1, 8);
		memcpy(hash, H, hashsize() / 8);
	}
	else
	{
		uint64_t counter = 0;
		size_t hb = hs;
		uint64_t hbk[16 * 8];
		memcpy(hbk, H, sizeof(hbk));
		for (size_t i = 0; i < hs; i += 1024)
		{
			size_t bytes = std::min(static_cast<size_t>(1024), hb)/8;
			tweak[0] = 0;
			tweak[1] = 255ULL << 56;
			memcpy(m, &counter, 8);
			transfunc(m, 1, 8);
			memcpy(hash, H, bytes);
			++counter;
			hash += bytes;
			hb -= 1024;
			memcpy(H, hbk, sizeof(hbk));
		}
	}
}


skein1024::skein1024(size_t hashsize) : hs(hashsize)
{
	validate_hash_size(hashsize, SIZE_MAX);
	H = h; // tests show that this helps MSVC++ optimizer a lot
#ifndef NO_OPTIMIZED_VERSIONS
#if defined(_MSC_VER) && defined(_M_X64)
	if (cpu_info::bmi2())
		transfunc = std::bind(&skein1024::transform_rorx, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	else
#endif
#endif
#ifdef NO_BIND_TO_FUNCTION
		transfunc = [this](void* m, uint64_t num_blks, size_t reallen) { transform(m, num_blks, reallen); };
#else
		transfunc = std::bind(&skein1024::transform, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
#endif

}

skein1024::~skein1024()
{
	clear();
}

void skein1024::clear()
{
	zero_memory(h.get(), h.bytes());
	zero_memory(m, sizeof(m));
	zero_memory(tweak, sizeof(tweak));
}

}

