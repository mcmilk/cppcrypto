/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "skein256.h"
#include "portability.h"
#include <memory.h>
#include <functional>

//#define CPPCRYPTO_DEBUG

#ifndef _M_X64
void Skein_256_Process_Block_mmx(uint64_t* T, uint64_t* X, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd);
#endif

namespace cppcrypto
{

void skein256::update(const unsigned char* data, size_t len)
{
	if (pos && pos + len > 32)
	{
		memcpy(m + pos, data, 32 - pos);
		transfunc(m, 1, 32);
		len -= 32 - pos;
		total += 32 - pos;
		data += 32 - pos;
		pos = 0;
	}
	if (len > 32)
	{
		size_t blocks = (len - 1) / 32;
		size_t bytes = blocks * 32;
		transfunc((void*)data, blocks, 32);
		len -= bytes;
		total += (bytes)* 8;
		data += bytes;
	}
	memcpy(m + pos, data, len);
	pos += len;
	total += len * 8;
}

void skein256::init()
{
	tweak[0] = 0ULL;
	tweak[1] = (1ULL << 62) | (4ULL << 56) | (1ULL << 63);
	pos = 0;
	total = 0;

	switch(hs)
	{
		case 256:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xFC9DA860D048B449;
			H[1] = 0x2FCA66479FA7D833;
			H[2] = 0xB33BC3896656840F;
			H[3] = 0x6A54E920FDE8DA69;
			return;
		case 224:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xC6098A8C9AE5EA0B;
			H[1] = 0x876D568608C5191C;
			H[2] = 0x99CB88D7D7F53884;
			H[3] = 0x384BDDB1AEDDB5DE;
			return;
		case 160:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0x1420231472825E98;
			H[1] = 0x2AC4E9A25A77E590;
			H[2] = 0xD47A58568838D63E;
			H[3] = 0x2DD2E4968586AB7D;
			return;
		case 128:
			tweak[1] = (1ULL << 62) | (48ULL << 56);
			H[0] = 0xE1111906964D7260;
			H[1] = 0x883DAAA77C8D811C;
			H[2] = 0x10080DF491960F7A;
			H[3] = 0xCCF7DDE5B45BC1C2;
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
	transfunc(m, 1, 32);
	pos = 0;
	total = 0;
	tweak[0] = 0ULL;
	tweak[1] = (1ULL << 62) | (48ULL << 56);
};


#define G(G0, G1, G2, G3, C0, C1) \
G0 += G1; \
G1 = rotatel64(G1, C0) ^ G0; \
G2 += G3; \
G3 = rotatel64(G3, C1) ^ G2;

#define KS(r) \
G0 += keys[(r + 1) % 5]; \
G1 += keys[(r + 2) % 5] + tweaks[(r + 1) % 3]; \
G2 += keys[(r + 3) % 5] + tweaks[(r + 2) % 3]; \
G3 += keys[(r + 4) % 5] + r + 1;

#define G8(r) \
G(G0, G1, G2, G3, 14, 16); \
G(G0, G3, G2, G1, 52, 57); \
G(G0, G1, G2, G3, 23, 40); \
G(G0, G3, G2, G1, 5, 37); \
KS(r); \
G(G0, G1, G2, G3, 25, 33); \
G(G0, G3, G2, G1, 46, 12); \
G(G0, G1, G2, G3, 58, 22); \
G(G0, G3, G2, G1, 32, 32); \
KS(r + 1);

void skein256::transform(void* mp, uint64_t num_blks, size_t reallen)
{
	uint64_t keys[5];
	uint64_t tweaks[3];

	for (uint64_t b = 0; b < num_blks; b++)
	{
		uint64_t M[4];
		uint64_t G0, G1, G2, G3;
		for (uint64_t i = 0; i < 32 / 8; i++)
		{
			M[i] = (reinterpret_cast<const uint64_t*>(mp)[b * 4 + i]);
		}

		memcpy(keys, H, sizeof(uint64_t) * 4);
		memcpy(tweaks, tweak, sizeof(uint64_t) * 2);
		tweaks[0] += reallen;
		tweaks[2] = tweaks[0] ^ tweaks[1];
		keys[4] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3];

		G0 = M[0] + keys[0];
		G1 = M[1] + keys[1];
		G2 = M[2] + keys[2];
		G3 = M[3] + keys[3];
		G1 += tweaks[0];
		G2 += tweaks[1];

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
	}

}

void skein256::final(unsigned char* hash)
{
	tweak[1] |= 1ULL << 63; // last block
	if (pos < 32)
		memset(m + pos, 0, 32 - pos);

	transfunc(m, 1, pos);

	// generate output
	memset(m, 0, 32);
	if (hs <= 256)
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
		uint64_t hbk[4 * 8];
		memcpy(hbk, H, sizeof(hbk));
		for (size_t i = 0; i < hs; i += 256)
		{
			size_t bytes = std::min(static_cast<size_t>(256), hb) / 8;
			tweak[0] = 0;
			tweak[1] = 255ULL << 56;
			memcpy(m, &counter, 8);
			transfunc(m, 1, 8);
			memcpy(hash, H, bytes);
			++counter;
			hash += bytes;
			hb -= 256;
			memcpy(H, hbk, sizeof(hbk));
		}
	}

}


skein256::skein256(size_t hashsize)
	: hs(hashsize)
{
	validate_hash_size(hashsize, SIZE_MAX);
	H = h; // tests show that this helps MSVC++ optimizer a lot
#ifndef NO_OPTIMIZED_VERSIONS
#ifndef _M_X64
#ifndef __clang__ // MMX code is very slow on clang compiles for some reason
	if (cpu_info::mmx())
		transfunc = [this](void* m, uint64_t num_blks, size_t reallen) { Skein_256_Process_Block_mmx(tweak, H, (unsigned char*)m, static_cast<size_t>(num_blks), reallen); };
	else
#endif
#endif
#endif
#ifdef NO_BIND_TO_FUNCTION
		transfunc = [this](void* m, uint64_t num_blks, size_t reallen) { transform(m, num_blks, reallen); };
#else
		transfunc = std::bind(&skein256::transform, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
#endif
}

skein256::~skein256()
{
	clear();
}

void skein256::clear()
{
	zero_memory(h.get(), h.bytes());
	zero_memory(m, sizeof(m));
	zero_memory(tweak, sizeof(tweak));
}


}
