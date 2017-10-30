/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "serpent.h"
#include "portability.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <algorithm>

#ifdef _MSC_VER
#define inline __forceinline
#endif

extern "C"
{
	void serpentEncrypt(uint32_t *, uint32_t *);
	void serpentDecrypt(uint32_t *, uint32_t *);
	void serpentGenKeyAsm(const uint32_t *, uint32_t *);
}

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	serpent256::serpent256()
	{
	}

	serpent192::serpent192()
	{
	}

	serpent128::serpent128()
	{
	}

	serpent256::~serpent256()
	{
		clear();
	}

	void serpent256::clear()
	{
		zero_memory(W, sizeof(W));
	}

	static inline void sbox0(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;
		r3 ^= r0;
		r1 &= r3;
		r4 ^= r2;
		r1 ^= r0;
		r0 |= r3;
		r0 ^= r4;
		r4 ^= r3;
		r3 ^= r2;
		r2 |= r1;
		r2 ^= r4;
		r4 = ~r4;
		r4 |= r1;
		r1 ^= r3;
		r1 ^= r4;
		r3 |= r0;
		r1 ^= r3;
		r4 ^= r3;
		w0 = r1;
		w1 = r4;
		w2 = r2;
		w3 = r0;
	}

	static inline void sbox1(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
		r0 = ~r0;
		r2 = ~r2;
		r4 = r0;
		r0 &= r1;
		r2 ^= r0;
		r0 |= r3;
		r3 ^= r2;
		r1 ^= r0;
		r0 ^= r4;
		r4 |= r1;
		r1 ^= r3;
		r2 |= r0;
		r2 &= r4;
		r0 ^= r1;
		r1 &= r2;
		r1 ^= r0;
		r0 &= r2;
		r0 ^= r4;
		w0 = r2;
		w1 = r0;
		w2 = r3;
		w3 = r1;
	}

	static inline void sbox2(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r0;
		r0 &= r2;
		r0 ^= r3;
		r2 ^= r1;
		r2 ^= r0;
		r3 |= r4;
		r3 ^= r1;
		r4 ^= r2;
		r1 = r3;
		r3 |= r4;
		r3 ^= r0;
		r0 &= r1;
		r4 ^= r0;
		r1 ^= r3;
		r1 ^= r4;
		r4 = ~r4;
		w0 = r2;
		w1 = r3;
		w2 = r1;
		w3 = r4;
	}

	static inline void sbox3(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r0;
		r0 |= r3;
		r3 ^= r1;
		r1 &= r4;
		r4 ^= r2;
		r2 ^= r3;
		r3 &= r0;
		r4 |= r1;
		r3 ^= r4;
		r0 ^= r1;
		r4 &= r0;
		r1 ^= r3;
		r4 ^= r2;
		r1 |= r0;
		r1 ^= r2;
		r0 ^= r3;
		r2 = r1;
		r1 |= r3;
		r1 ^= r0;
		w0 = r1;
		w1 = r2;
		w2 = r3;
		w3 = r4;
	}

	static inline void sbox4(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
		r1 ^= r3;
		r3 = ~r3;
		r2 ^= r3;
		r3 ^= r0;
		r4 = r1;
		r1 &= r3;
		r1 ^= r2;
		r4 ^= r3;
		r0 ^= r4;
		r2 &= r4;
		r2 ^= r0;
		r0 &= r1;
		r3 ^= r0;
		r4 |= r1;
		r4 ^= r0;
		r0 |= r3;
		r0 ^= r2;
		r2 &= r3;
		r0 = ~r0;
		r4 ^= r2;
		w0 = r1;
		w1 = r4;
		w2 = r0;
		w3 = r3;
	}

	static inline void sbox5(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
		r0 ^= r1;
		r1 ^= r3;
		r3 = ~r3;
		r4 = r1;
		r1 &= r0;
		r2 ^= r3;
		r1 ^= r2;
		r2 |= r4;
		r4 ^= r3;
		r3 &= r1;
		r3 ^= r0;
		r4 ^= r1;
		r4 ^= r2;
		r2 ^= r0;
		r0 &= r3;
		r2 = ~r2;
		r0 ^= r4;
		r4 |= r3;
		r2 ^= r4;
		w0 = r1;
		w1 = r3;
		w2 = r0;
		w3 = r2;
	}

	static inline void sbox6(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r3;
		r2 = ~r2;
		r3 &= r0;
		r0 ^= r4;
		r3 ^= r2;
		r2 |= r4;
		r1 ^= r3;
		r2 ^= r0;
		r0 |= r1;
		r2 ^= r1;
		r4 ^= r0;
		r0 |= r3;
		r0 ^= r2;
		r4 ^= r3;
		r4 ^= r0;
		r3 = ~r3;
		r2 &= r4;
		r2 ^= r3;
		w0 = r0;
		w1 = r1;
		w2 = r4;
		w3 = r2;
	}

	static inline void sbox7(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;
		r1 |= r2;
		r1 ^= r3;
		r4 ^= r2;
		r2 ^= r1;
		r3 |= r4;
		r3 &= r0;
		r4 ^= r2;
		r3 ^= r1;
		r1 |= r4;
		r1 ^= r0;
		r0 |= r4;
		r0 ^= r2;
		r1 ^= r4;
		r2 ^= r1;
		r1 &= r0;
		r1 ^= r4;
		r2 = ~r2;
		r2 |= r0;
		r4 ^= r2;
		w0 = r4;
		w1 = r3;
		w2 = r1;
		w3 = r0;
	}

	static inline void isbox0(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;

		r2 = ~r2;
		r1 |= r0;
		r4 = ~r4;
		r1 ^= r2;
		r2 |= r4;
		r1 ^= r3;
		r0 ^= r4;
		r2 ^= r0;
		r0 &= r3;
		r4 ^= r0;
		r0 |= r1;
		r0 ^= r2;
		r3 ^= r4;
		r2 ^= r1;
		r3 ^= r0;
		r3 ^= r1;
		r2 &= r3;
		r4 ^= r2;
		w0 = r0;
		w1 = r4;
		w2 = r1;
		w3 = r3;
	}

	static inline void isbox1(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;

		r1 ^= r3;
		r3 &= r1;
		r4 ^= r2;
		r3 ^= r0;
		r0 |= r1;
		r2 ^= r3;
		r0 ^= r4;
		r0 |= r2;
		r1 ^= r3;
		r0 ^= r1;
		r1 |= r3;
		r1 ^= r0;
		r4 = ~r4;
		r4 ^= r1;
		r1 |= r0;
		r1 ^= r0;
		r1 |= r4;
		r3 ^= r1;
		w0 = r4;
		w1 = r0;
		w2 = r3;
		w3 = r2;
	}

	static inline void isbox2(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;

		r2 ^= r3;
		r3 ^= r0;
		r4 = r3;
		r3 &= r2;
		r3 ^= r1;
		r1 |= r2;
		r1 ^= r4;
		r4 &= r3;
		r2 ^= r3;
		r4 &= r0;
		r4 ^= r2;
		r2 &= r1;
		r2 |= r0;
		r3 = ~r3;
		r2 ^= r3;
		r0 ^= r3;
		r0 &= r1;
		r3 ^= r4;
		r3 ^= r0;
		w0 = r1;
		w1 = r4;
		w2 = r2;
		w3 = r3;
	}

	static inline void isbox3(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;

		r2 ^= r1;
		r0 ^= r2;
		r4 &= r2;
		r4 ^= r0;
		r0 &= r1;
		r1 ^= r3;
		r3 |= r4;
		r2 ^= r3;
		r0 ^= r3;
		r1 ^= r4;
		r3 &= r2;
		r3 ^= r1;
		r1 ^= r0;
		r1 |= r2;
		r0 ^= r3;
		r1 ^= r4;
		r0 ^= r1;
		w0 = r2;
		w1 = r1;
		w2 = r3;
		w3 = r0;
	}

	static inline void isbox4(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
		r2 &= r3;
		r2 ^= r1;
		r1 |= r3;
		r1 &= r0;
		r4 ^= r2;
		r4 ^= r1;
		r1 &= r2;
		r0 = ~r0;
		r3 ^= r4;
		r1 ^= r3;
		r3 &= r0;
		r3 ^= r2;
		r0 ^= r1;
		r2 &= r0;
		r3 ^= r0;
		r2 ^= r4;
		r2 |= r3;
		r3 ^= r0;
		r2 ^= r1;
		w0 = r0;
		w1 = r3;
		w2 = r2;
		w3 = r4;
	}

	static inline void isbox5(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r3;
		r1 = ~r1;
		r2 ^= r1;
		r3 |= r0;
		r3 ^= r2;
		r2 |= r1;
		r2 &= r0;
		r4 ^= r3;
		r2 ^= r4;
		r4 |= r0;
		r4 ^= r1;
		r1 &= r2;
		r1 ^= r3;
		r4 ^= r2;
		r3 &= r4;
		r4 ^= r1;
		r3 ^= r4;
		r4 = ~r4;
		r3 ^= r0;
		w0 = r1;
		w1 = r4;
		w2 = r3;
		w3 = r2;
	}

	static inline void isbox6(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
		r0 ^= r2;
		r2 &= r0;
		r4 ^= r3;
		r2 = ~r2;
		r3 ^= r1;
		r2 ^= r3;
		r4 |= r0;
		r0 ^= r2;
		r3 ^= r4;
		r4 ^= r1;
		r1 &= r3;
		r1 ^= r0;
		r0 ^= r3;
		r0 |= r2;
		r3 ^= r1;
		r4 ^= r0;
		w0 = r1;
		w1 = r2;
		w2 = r4;
		w3 = r3;
	}

	static inline void isbox7(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		uint32_t r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
		r2 ^= r0;
		r0 &= r3;
		r4 |= r3;
		r2 = ~r2;
		r3 ^= r1;
		r1 |= r0;
		r0 ^= r2;
		r2 &= r4;
		r3 &= r4;
		r1 ^= r2;
		r2 ^= r0;
		r0 |= r2;
		r4 ^= r1;
		r0 ^= r3;
		r3 ^= r4;
		r4 |= r0;
		r3 ^= r2;
		r4 ^= r2;
		w0 = r3;
		w1 = r0;
		w2 = r1;
		w3 = r4;
	}

	static inline void lt(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		w0 = rotatel32(w0, 13);
		w2 = rotatel32(w2, 3);
		w1 = w1 ^ w0 ^ w2;
		w3 = w3 ^ w2 ^ (w0 << 3);
		w1 = rotatel32(w1, 1);
		w3 = rotatel32(w3, 7);
		w0 = w0 ^ w1 ^ w3;
		w2 = w2 ^ w3 ^ (w1 << 7);
		w0 = rotatel32(w0, 5);
		w2 = rotatel32(w2, 22);
	}

	static inline void ilt(uint32_t& w0, uint32_t& w1, uint32_t& w2, uint32_t& w3)
	{
		w2 = rotater32(w2, 22);
		w0 = rotater32(w0, 5);
		w2 = w2 ^ w3 ^ (w1 << 7);
		w0 = w0 ^ w1 ^ w3;
		w3 = rotater32(w3, 7);
		w1 = rotater32(w1, 1);
		w3 = w3 ^ w2 ^ (w0 << 3);
		w1 = w1 ^ w0 ^ w2;
		w2 = rotater32(w2, 3);
		w0 = rotater32(w0, 13);
	}

	bool serpent256::init(const unsigned char* key, block_cipher::direction direction)
	{
#ifdef SERPENT_AS_TNEPRES
		W[7] = swap_uint32(*(((const uint32_t*)key) + 0));
		W[6] = swap_uint32(*(((const uint32_t*)key) + 1));
		W[5] = swap_uint32(*(((const uint32_t*)key) + 2));
		W[4] = swap_uint32(*(((const uint32_t*)key) + 3));
		W[3] = swap_uint32(*(((const uint32_t*)key) + 4));
		W[2] = swap_uint32(*(((const uint32_t*)key) + 5));
		W[1] = swap_uint32(*(((const uint32_t*)key) + 6));
		W[0] = swap_uint32(*(((const uint32_t*)key) + 7));
#else
		W[0] = *(((const uint32_t*)key) + 0);
		W[1] = *(((const uint32_t*)key) + 1);
		W[2] = *(((const uint32_t*)key) + 2);
		W[3] = *(((const uint32_t*)key) + 3);
		W[4] = *(((const uint32_t*)key) + 4);
		W[5] = *(((const uint32_t*)key) + 5);
		W[6] = *(((const uint32_t*)key) + 6);
		W[7] = *(((const uint32_t*)key) + 7);
#endif

		return do_init();
	}

	bool serpent256::do_init()
	{
#ifndef _M_X64
		serpentGenKeyAsm(W, &W[8]);
		return true;
#endif

		for (uint32_t i = 8; i < 140; i++)
			W[i] = rotatel32(W[i - 8] ^ W[i - 5] ^ W[i - 3] ^ W[i - 1] ^ 0x9e3779b9 ^ (i - 8), 11);

		sbox3(W[8], W[9], W[10], W[11]);
		sbox2(W[12], W[13], W[14], W[15]);
		sbox1(W[16], W[17], W[18], W[19]);
		sbox0(W[20], W[21], W[22], W[23]);
		sbox7(W[24], W[25], W[26], W[27]);
		sbox6(W[28], W[29], W[30], W[31]);
		sbox5(W[32], W[33], W[34], W[35]);
		sbox4(W[36], W[37], W[38], W[39]);
		sbox3(W[40], W[41], W[42], W[43]);
		sbox2(W[44], W[45], W[46], W[47]);
		sbox1(W[48], W[49], W[50], W[51]);
		sbox0(W[52], W[53], W[54], W[55]);
		sbox7(W[56], W[57], W[58], W[59]);
		sbox6(W[60], W[61], W[62], W[63]);
		sbox5(W[64], W[65], W[66], W[67]);
		sbox4(W[68], W[69], W[70], W[71]);
		sbox3(W[72], W[73], W[74], W[75]);
		sbox2(W[76], W[77], W[78], W[79]);
		sbox1(W[80], W[81], W[82], W[83]);
		sbox0(W[84], W[85], W[86], W[87]);
		sbox7(W[88], W[89], W[90], W[91]);
		sbox6(W[92], W[93], W[94], W[95]);
		sbox5(W[96], W[97], W[98], W[99]);
		sbox4(W[100], W[101], W[102], W[103]);
		sbox3(W[104], W[105], W[106], W[107]);
		sbox2(W[108], W[109], W[110], W[111]);
		sbox1(W[112], W[113], W[114], W[115]);
		sbox0(W[116], W[117], W[118], W[119]);
		sbox7(W[120], W[121], W[122], W[123]);
		sbox6(W[124], W[125], W[126], W[127]);
		sbox5(W[128], W[129], W[130], W[131]);
		sbox4(W[132], W[133], W[134], W[135]);
		sbox3(W[136], W[137], W[138], W[139]);

#ifdef CPPCRYPTO_DEBUG
		printf("my serpent:\n");
		for (int i = 0; i < 140; i++)
			printf("W[%d] = %04x\n", i, W[i]);
#endif

		return true;
	}

#define R(w, s) \
	x[0] ^= W[w*4+8]; \
	x[1] ^= W[w*4+9]; \
	x[2] ^= W[w*4+10]; \
	x[3] ^= W[w*4+11]; \
	s(x[0], x[1], x[2], x[3]); \
	lt(x[0], x[1], x[2], x[3]);

#define IR(w, s) \
	ilt(x[0], x[1], x[2], x[3]); \
	s(x[0], x[1], x[2], x[3]); \
	x[0] ^= W[w*4+8]; \
	x[1] ^= W[w*4+9]; \
	x[2] ^= W[w*4+10]; \
	x[3] ^= W[w*4+11];

	void serpent256::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint32_t x[4];
#ifndef _M_X64
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef SERPENT_AS_TNEPRES
		x[0] = swap_uint32(*(((const uint32_t*)in) + 0));
		x[1] = swap_uint32(*(((const uint32_t*)in) + 1));
		x[2] = swap_uint32(*(((const uint32_t*)in) + 2));
		x[3] = swap_uint32(*(((const uint32_t*)in) + 3));
		serpentEncrypt(x, &W[8]);
		*(((uint32_t*)out) + 0) = swap_uint32(x[0]);
		*(((uint32_t*)out) + 1) = swap_uint32(x[1]);
		*(((uint32_t*)out) + 2) = swap_uint32(x[2]);
		*(((uint32_t*)out) + 3) = swap_uint32(x[3]);
#else
		x[3] = (*(((const uint32_t*)in) + 0));
		x[2] = (*(((const uint32_t*)in) + 1));
		x[1] = (*(((const uint32_t*)in) + 2));
		x[0] = (*(((const uint32_t*)in) + 3));
		serpentEncrypt(x, &W[8]);
		*(((uint32_t*)out) + 0) = (x[3]);
		*(((uint32_t*)out) + 1) = (x[2]);
		*(((uint32_t*)out) + 2) = (x[1]);
		*(((uint32_t*)out) + 3) = (x[0]);
#endif
		return;
#endif
#endif
#ifdef SERPENT_AS_TNEPRES
		x[3] = swap_uint32(*(((const uint32_t*)in) + 0));
		x[2] = swap_uint32(*(((const uint32_t*)in) + 1));
		x[1] = swap_uint32(*(((const uint32_t*)in) + 2));
		x[0] = swap_uint32(*(((const uint32_t*)in) + 3));
#else
		x[0] = *(((const uint32_t*)in) + 0);
		x[1] = *(((const uint32_t*)in) + 1);
		x[2] = *(((const uint32_t*)in) + 2);
		x[3] = *(((const uint32_t*)in) + 3);
#endif

#ifdef CPPCRYPTO_DEBUG
		printf("my serpent:\n");
		printf("x[0]-x4: %04x %04x %04x %04x\n", x[0], x[1], x[2], x[3]);
#endif

		R(0, sbox0); R(1, sbox1); R(2, sbox2); R(3, sbox3); R(4, sbox4); R(5, sbox5); R(6, sbox6); R(7, sbox7);
		R(8, sbox0); R(9, sbox1); R(10, sbox2); R(11, sbox3); R(12, sbox4); R(13, sbox5); R(14, sbox6); R(15, sbox7);
		R(16, sbox0); R(17, sbox1); R(18, sbox2); R(19, sbox3); R(20, sbox4); R(21, sbox5); R(22, sbox6); R(23, sbox7);
		R(24, sbox0); R(25, sbox1); R(26, sbox2); R(27, sbox3); R(28, sbox4); R(29, sbox5); R(30, sbox6);

		x[0] ^= W[132];
		x[1] ^= W[133];
		x[2] ^= W[134];
		x[3] ^= W[135];
		sbox7(x[0], x[1], x[2], x[3]);

		x[0] ^= W[136];
		x[1] ^= W[137];
		x[2] ^= W[138];
		x[3] ^= W[139];

#ifdef CPPCRYPTO_DEBUG
		printf("round 32: %04x %04x %04x %04x\n", x[0], x[1], x[2], x[3]);
#endif

#ifdef SERPENT_AS_TNEPRES
		*(((uint32_t*)out) + 0) = swap_uint32(x[3]);
		*(((uint32_t*)out) + 1) = swap_uint32(x[2]);
		*(((uint32_t*)out) + 2) = swap_uint32(x[1]);
		*(((uint32_t*)out) + 3) = swap_uint32(x[0]);
#else
		*(((uint32_t*)out) + 0) = x[0];
		*(((uint32_t*)out) + 1) = x[1];
		*(((uint32_t*)out) + 2) = x[2];
		*(((uint32_t*)out) + 3) = x[3];
#endif

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 128 / 8; i++)
			printf("%02X", out[i]);
		printf("\n");
#endif
	}

	void serpent256::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint32_t x[4];
#ifndef _M_X64
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef SERPENT_AS_TNEPRES
		x[0] = swap_uint32(*(((const uint32_t*)in) + 0));
		x[1] = swap_uint32(*(((const uint32_t*)in) + 1));
		x[2] = swap_uint32(*(((const uint32_t*)in) + 2));
		x[3] = swap_uint32(*(((const uint32_t*)in) + 3));
		serpentDecrypt(x, &W[8]);
		*(((uint32_t*)out) + 0) = swap_uint32(x[0]);
		*(((uint32_t*)out) + 1) = swap_uint32(x[1]);
		*(((uint32_t*)out) + 2) = swap_uint32(x[2]);
		*(((uint32_t*)out) + 3) = swap_uint32(x[3]);
#else
		x[3] = *(((const uint32_t*)in) + 0);
		x[2] = *(((const uint32_t*)in) + 1);
		x[1] = *(((const uint32_t*)in) + 2);
		x[0] = *(((const uint32_t*)in) + 3);
		serpentDecrypt(x, &W[8]); 
		*(((uint32_t*)out) + 0) = (x[3]);
		*(((uint32_t*)out) + 1) = (x[2]);
		*(((uint32_t*)out) + 2) = (x[1]);
		*(((uint32_t*)out) + 3) = (x[0]);
#endif
		return;
#endif
#endif

#ifdef SERPENT_AS_TNEPRES
		x[3] = swap_uint32(*(((const uint32_t*)in) + 0));
		x[2] = swap_uint32(*(((const uint32_t*)in) + 1));
		x[1] = swap_uint32(*(((const uint32_t*)in) + 2));
		x[0] = swap_uint32(*(((const uint32_t*)in) + 3));
#else
		x[0] = *(((const uint32_t*)in) + 0);
		x[1] = *(((const uint32_t*)in) + 1);
		x[2] = *(((const uint32_t*)in) + 2);
		x[3] = *(((const uint32_t*)in) + 3);
#endif

#ifdef CPPCRYPTO_DEBUG
		printf("my serpent decrypt:\n");
		printf("x[0]-x4: %04x %04x %04x %04x\n", x[0], x[1], x[2], x[3]);
#endif

		x[0] ^= W[136];
		x[1] ^= W[137];
		x[2] ^= W[138];
		x[3] ^= W[139];

		isbox7(x[0], x[1], x[2], x[3]);
		x[0] ^= W[132];
		x[1] ^= W[133];
		x[2] ^= W[134];
		x[3] ^= W[135];

#ifdef CPPCRYPTO_DEBUG
		printf("round 31: %04x %04x %04x %04x\n", x[0], x[1], x[2], x[3]);
#endif

		IR(30, isbox6); IR(29, isbox5); IR(28, isbox4); IR(27, isbox3); IR(26, isbox2); IR(25, isbox1); IR(24, isbox0); IR(23, isbox7);
		IR(22, isbox6); IR(21, isbox5); IR(20, isbox4); IR(19, isbox3); IR(18, isbox2); IR(17, isbox1); IR(16, isbox0); IR(15, isbox7);
		IR(14, isbox6); IR(13, isbox5); IR(12, isbox4); IR(11, isbox3); IR(10, isbox2); IR(9, isbox1); IR(8, isbox0); IR(7, isbox7);
		IR(6, isbox6); IR(5, isbox5); IR(4, isbox4); IR(3, isbox3); IR(2, isbox2); IR(1, isbox1); IR(0, isbox0);

#ifdef SERPENT_AS_TNEPRES
		*(((uint32_t*)out) + 0) = swap_uint32(x[3]);
		*(((uint32_t*)out) + 1) = swap_uint32(x[2]);
		*(((uint32_t*)out) + 2) = swap_uint32(x[1]);
		*(((uint32_t*)out) + 3) = swap_uint32(x[0]);
#else
		*(((uint32_t*)out) + 0) = x[0];
		*(((uint32_t*)out) + 1) = x[1];
		*(((uint32_t*)out) + 2) = x[2];
		*(((uint32_t*)out) + 3) = x[3];
#endif
	}

	bool serpent128::init(const unsigned char* key, block_cipher::direction direction)
	{
#ifdef SERPENT_AS_TNEPRES
		W[3] = swap_uint32(*(((const uint32_t*)key) + 0));
		W[2] = swap_uint32(*(((const uint32_t*)key) + 1));
		W[1] = swap_uint32(*(((const uint32_t*)key) + 2));
		W[0] = swap_uint32(*(((const uint32_t*)key) + 3));
#else
		W[0] = *(((const uint32_t*)key) + 0);
		W[1] = *(((const uint32_t*)key) + 1);
		W[2] = *(((const uint32_t*)key) + 2);
		W[3] = *(((const uint32_t*)key) + 3);
#endif
		W[4] = 0x01;
		W[5] = 0;
		W[6] = 0;
		W[7] = 0;

		return do_init();
	}

	bool serpent192::init(const unsigned char* key, block_cipher::direction direction)
	{
#ifdef SERPENT_AS_TNEPRES
		W[5] = swap_uint32(*(((const uint32_t*)key) + 0));
		W[4] = swap_uint32(*(((const uint32_t*)key) + 1));
		W[3] = swap_uint32(*(((const uint32_t*)key) + 2));
		W[2] = swap_uint32(*(((const uint32_t*)key) + 3));
		W[1] = swap_uint32(*(((const uint32_t*)key) + 4));
		W[0] = swap_uint32(*(((const uint32_t*)key) + 5));
#else
		W[0] = *(((const uint32_t*)key) + 0);
		W[1] = *(((const uint32_t*)key) + 1);
		W[2] = *(((const uint32_t*)key) + 2);
		W[3] = *(((const uint32_t*)key) + 3);
		W[4] = *(((const uint32_t*)key) + 4);
		W[5] = *(((const uint32_t*)key) + 5);
#endif
		W[6] = 0x01;
		W[7] = 0;

		return do_init();
	}

}
