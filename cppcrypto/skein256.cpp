/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "cpuinfo.h"
#include "skein256.h"

//#define DEBUG

#ifndef _M_X64
void Skein_256_Process_Block_mmx(uint64_t* T, uint64_t* X, const uint8_t *blkPtr, size_t blkCnt, size_t byteCntAdd);
#endif

namespace cppcrypto
{

	void skein256_256::update(const uint8_t* data, size_t len)
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
		memcpy(m, data, len);
		pos += len;
		total += len * 8;
	}

	void skein256_256::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56); // should be: 112 << 56

		H[0] = 0xFC9DA860D048B449;
		H[1] = 0x2FCA66479FA7D833;
		H[2] = 0xB33BC3896656840F;
		H[3] = 0x6A54E920FDE8DA69;

		pos = 0;
		total = 0;
	};


	void skein256_256::transform(void* m, uint64_t num_blks, size_t reallen)
	{
		uint64_t keys[5];
		uint64_t tweaks[3];

		for (uint64_t b = 0; b < num_blks; b++)
		{
			uint64_t M[4];
			uint64_t G0, G1, G2, G3;
			for (uint64_t i = 0; i < 32 / 8; i++)
			{
				M[i] = (reinterpret_cast<const uint64_t*>(m)[b * 4 + i]);
			}

			memcpy(keys, H, sizeof(uint64_t)*4);
			memcpy(tweaks, tweak, sizeof(uint64_t)*2);
			tweaks[0] += reallen;
			tweaks[2] = tweaks[0] ^ tweaks[1];
			keys[4] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3];

#ifdef DEBUG
			printf("transform; tweaks: ");
			for (int i = 0; i < 3; i++)
				printf("%llx ", tweaks[i]);
			printf("\nkeys:\n");
			for (int i = 0; i < 5; i++)
				printf("%llx ", keys[i]);
			printf("\n");
#endif

			G0 = M[0] + keys[0];
			G1 = M[1] + keys[1];
			G2 = M[2] + keys[2];
			G3 = M[3] + keys[3];
			G1 += tweaks[0];
			G2 += tweaks[1];

#ifdef DEBUG
			printf("message:\n");
			for (int i = 0; i < 4; i++)
				printf("%llx ", M[i]);
			printf("\n");
#endif


#ifdef DEBUG
			printf("before rounds:\n");
			for (int i = 0; i < 4; i++)
				printf("%llx ", G[i]);
			printf("\n");
#endif
			
			// The loop is fully unrolled for performance reasons
			//for (int s = 0; s < 72 / 8; s++)
			{
				// ZERO
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 1) % 5];
				G1 += keys[(0 * 2 + 2) % 5] + tweaks[(0 * 2 + 1) % 3];
				G2 += keys[(0 * 2 + 3) % 5] + tweaks[(0 * 2 + 2) % 3];
				G3 += keys[(0 * 2 + 4) % 5] + 0 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 0 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 2) % 5];
				G1 += keys[(0 * 2 + 3) % 5] + tweaks[(0 * 2 + 2) % 3];
				G2 += keys[(0 * 2 + 4) % 5] + tweaks[(0 * 2 + 3) % 3];
				G3 += keys[(0 * 2 + 5) % 5] + 0 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 0 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// ONE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 1) % 5];
				G1 += keys[(1 * 2 + 2) % 5] + tweaks[(1 * 2 + 1) % 3];
				G2 += keys[(1 * 2 + 3) % 5] + tweaks[(1 * 2 + 2) % 3];
				G3 += keys[(1 * 2 + 4) % 5] + 1 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 1 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 2) % 5];
				G1 += keys[(1 * 2 + 3) % 5] + tweaks[(1 * 2 + 2) % 3];
				G2 += keys[(1 * 2 + 4) % 5] + tweaks[(1 * 2 + 3) % 3];
				G3 += keys[(1 * 2 + 5) % 5] + 1 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 1 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// TWO
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 1) % 5];
				G1 += keys[(2 * 2 + 2) % 5] + tweaks[(2 * 2 + 1) % 3];
				G2 += keys[(2 * 2 + 3) % 5] + tweaks[(2 * 2 + 2) % 3];
				G3 += keys[(2 * 2 + 4) % 5] + 2 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 2 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 2) % 5];
				G1 += keys[(2 * 2 + 3) % 5] + tweaks[(2 * 2 + 2) % 3];
				G2 += keys[(2 * 2 + 4) % 5] + tweaks[(2 * 2 + 3) % 3];
				G3 += keys[(2 * 2 + 5) % 5] + 2 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 2 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 1) % 5];
				G1 += keys[(3 * 2 + 2) % 5] + tweaks[(3 * 2 + 1) % 3];
				G2 += keys[(3 * 2 + 3) % 5] + tweaks[(3 * 2 + 2) % 3];
				G3 += keys[(3 * 2 + 4) % 5] + 3 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 2) % 5];
				G1 += keys[(3 * 2 + 3) % 5] + tweaks[(3 * 2 + 2) % 3];
				G2 += keys[(3 * 2 + 4) % 5] + tweaks[(3 * 2 + 3) % 3];
				G3 += keys[(3 * 2 + 5) % 5] + 3 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// FOUR

				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 1) % 5];
				G1 += keys[(4 * 2 + 2) % 5] + tweaks[(4 * 2 + 1) % 3];
				G2 += keys[(4 * 2 + 3) % 5] + tweaks[(4 * 2 + 2) % 3];
				G3 += keys[(4 * 2 + 4) % 5] + 4 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 2) % 5];
				G1 += keys[(4 * 2 + 3) % 5] + tweaks[(4 * 2 + 2) % 3];
				G2 += keys[(4 * 2 + 4) % 5] + tweaks[(4 * 2 + 3) % 3];
				G3 += keys[(4 * 2 + 5) % 5] + 4 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// FIVE

				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 1) % 5];
				G1 += keys[(5 * 2 + 2) % 5] + tweaks[(5 * 2 + 1) % 3];
				G2 += keys[(5 * 2 + 3) % 5] + tweaks[(5 * 2 + 2) % 3];
				G3 += keys[(5 * 2 + 4) % 5] + 5 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 2) % 5];
				G1 += keys[(5 * 2 + 3) % 5] + tweaks[(5 * 2 + 2) % 3];
				G2 += keys[(5 * 2 + 4) % 5] + tweaks[(5 * 2 + 3) % 3];
				G3 += keys[(5 * 2 + 5) % 5] + 5 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// SIX

				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 1) % 5];
				G1 += keys[(6 * 2 + 2) % 5] + tweaks[(6 * 2 + 1) % 3];
				G2 += keys[(6 * 2 + 3) % 5] + tweaks[(6 * 2 + 2) % 3];
				G3 += keys[(6 * 2 + 4) % 5] + 6 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 2) % 5];
				G1 += keys[(6 * 2 + 3) % 5] + tweaks[(6 * 2 + 2) % 3];
				G2 += keys[(6 * 2 + 4) % 5] + tweaks[(6 * 2 + 3) % 3];
				G3 += keys[(6 * 2 + 5) % 5] + 6 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif
				// SEVEN

				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 1) % 5];
				G1 += keys[(7 * 2 + 2) % 5] + tweaks[(7 * 2 + 1) % 3];
				G2 += keys[(7 * 2 + 3) % 5] + tweaks[(7 * 2 + 2) % 3];
				G3 += keys[(7 * 2 + 4) % 5] + 7 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 2) % 5];
				G1 += keys[(7 * 2 + 3) % 5] + tweaks[(7 * 2 + 2) % 3];
				G2 += keys[(7 * 2 + 4) % 5] + tweaks[(7 * 2 + 3) % 3];
				G3 += keys[(7 * 2 + 5) % 5] + 7 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// EIGHT

				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 14) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 16) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 52) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 57) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 23) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 40) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 5) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 37) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 1) % 5];
				G1 += keys[(8 * 2 + 2) % 5] + tweaks[(8 * 2 + 1) % 3];
				G2 += keys[(8 * 2 + 3) % 5] + tweaks[(8 * 2 + 2) % 3];
				G3 += keys[(8 * 2 + 4) % 5] + 8 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 25) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 33) ^ G2;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G3;
				G3 = _rotl64(G3, 46) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 12) ^ G2;

				G0 += G1;
				G1 = _rotl64(G1, 58) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 22) ^ G2;

				G0 += G3;
				G3 = _rotl64(G3, 32) ^ G0;
				G2 += G1;
				G1 = _rotl64(G1, 32) ^ G2;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 2) % 5];
				G1 += keys[(8 * 2 + 3) % 5] + tweaks[(8 * 2 + 2) % 3];
				G2 += keys[(8 * 2 + 4) % 5] + tweaks[(8 * 2 + 3) % 3];
				G3 += keys[(8 * 2 + 5) % 5] + 8 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 4; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


			}
			tweaks[1] &= ~(64ULL << 56);
			tweak[0] = tweaks[0];
			tweak[1] = tweaks[1];
			//for (int i = 0; i < 4; i++)
				H[0] = G0 ^ M[0];
				H[1] = G1 ^ M[1];
				H[2] = G2 ^ M[2];
				H[3] = G3 ^ M[3];
		}

	}

	void skein256_256::final(uint8_t* hash)
	{
		tweak[1] |= 1ULL << 63; // last block
		if (pos < 32)
			memset(m + pos, 0, 32 - pos);

		transfunc(m, 1, pos);

		// generate output
		tweak[0] = 0;
		tweak[1] = 255ULL << 56;
		memset(m, 0, 32);
		transfunc(m, 1, 8);

		memcpy(hash, H, hashbitlen() / 8);
	}

	void skein256_224::init()
	{
		tweak[0] = 0ULL;
		tweak[1] = (1ULL << 62) | (48ULL << 56);

		H[0] = 0xC6098A8C9AE5EA0B;
		H[1] = 0x876D568608C5191C;
		H[2] = 0x99CB88D7D7F53884;
		H[3] = 0x384BDDB1AEDDB5DE;

		pos = 0;
		total = 0;
	};

	skein256_256::skein256_256()
	{
		H = (uint64_t*)_aligned_malloc(sizeof(uint64_t) * 4, 32);
		H = (uint64_t*)_aligned_malloc(sizeof(uint64_t) * 8, 32);
#ifndef _M_X64
		if (cpu_info::mmx())
			transfunc = [this](void* m, uint64_t num_blks, size_t reallen) { Skein_256_Process_Block_mmx(tweak, H, (uint8_t*)m, static_cast<size_t>(num_blks), reallen); };
		else
#endif
			transfunc = bind(&skein256_256::transform, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	}

	skein256_256::~skein256_256()
	{
		_aligned_free(H);
	}

}
