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
		memcpy(m, data, len);
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

#ifdef DEBUG
			printf("transform; tweaks: ");
			for (int i = 0; i < 3; i++)
				printf("%llx ", tweaks[i]);
			printf("\nkeys:\n");
			for (int i = 0; i < 9; i++)
				printf("%llx ", keys[i]);
			printf("\n");
#endif

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

#ifdef DEBUG
			printf("message:\n");
			for (int i = 0; i < 8; i++)
				printf("%llx ", M[i]);
			printf("\n");
#endif


#ifdef DEBUG
			printf("before rounds:\n");
			for (int i = 0; i < 8; i++)
				printf("%llx ", G[i]);
			printf("\n");
#endif

			// The loop is fully unrolled for performance reasons
			//
//			for (int s = 0; s < 72 / 8; s++)
//			{
			// ZERO
                // four rounds
                G0 += G1;
                G1 = _rotl64(G1, 46) ^ G0;
                G2 += G3;
                G3 = _rotl64(G3, 36) ^ G2;
                G4 += G5;
                G5 = _rotl64(G5, 19) ^ G4;
                G6 += G7;
                G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
                printf("round %d:\n", s * 8 + 1);
                for (int i = 0; i < 8; i++)
                        printf("%llx ", G[i]);
                printf("\n");
#endif

                G2 += G1;
                G1 = _rotl64(G1, 33) ^ G2;
                G4 += G7;
                G7 = _rotl64(G7, 27) ^ G4;
                G6 += G5;
                G5 = _rotl64(G5, 14) ^ G6;
                G0 += G3;
                G3 = _rotl64(G3, 42) ^ G0;

                G4 += G1;
                G1 = _rotl64(G1, 17) ^ G4;
                G6 += G3;
                G3 = _rotl64(G3, 49) ^ G6;
                G0 += G5;
                G5 = _rotl64(G5, 36) ^ G0;
                G2 += G7;
                G7 = _rotl64(G7, 39) ^ G2;

                G6 += G1;
                G1 = _rotl64(G1, 44) ^ G6;
                G0 += G7;
                G7 = _rotl64(G7, 9) ^ G0;
                G2 += G5;
                G5 = _rotl64(G5, 54) ^ G2;
                G4 += G3;
                G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 1) % 9];
				G1 += keys[(0 * 2 + 2) % 9];
				G2 += keys[(0 * 2 + 3) % 9];
				G3 += keys[(0 * 2 + 4) % 9];
				G4 += keys[(0 * 2 + 5) % 9];
				G5 += keys[(0 * 2 + 6) % 9] + tweaks[(0 * 2 + 1) % 3];
				G6 += keys[(0 * 2 + 7) % 9] + tweaks[(0 * 2 + 2) % 3];
				G7 += keys[(0 * 2 + 8) % 9] + 0 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 2) % 9];
				G1 += keys[(0 * 2 + 3) % 9];
				G2 += keys[(0 * 2 + 4) % 9];
				G3 += keys[(0 * 2 + 5) % 9];
				G4 += keys[(0 * 2 + 6) % 9];
				G5 += keys[(0 * 2 + 7) % 9] + tweaks[(0 * 2 + 2) % 3];
				G6 += keys[(0 * 2 + 8) % 9] + tweaks[(0 * 2 + 3) % 3];
				G7 += keys[(0 * 2 + 9) % 9] + 0 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// ONE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 1) % 9];
				G1 += keys[(1 * 2 + 2) % 9];
				G2 += keys[(1 * 2 + 3) % 9];
				G3 += keys[(1 * 2 + 4) % 9];
				G4 += keys[(1 * 2 + 5) % 9];
				G5 += keys[(1 * 2 + 6) % 9] + tweaks[(1 * 2 + 1) % 3];
				G6 += keys[(1 * 2 + 7) % 9] + tweaks[(1 * 2 + 2) % 3];
				G7 += keys[(1 * 2 + 8) % 9] + 1 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 2) % 9];
				G1 += keys[(1 * 2 + 3) % 9];
				G2 += keys[(1 * 2 + 4) % 9];
				G3 += keys[(1 * 2 + 5) % 9];
				G4 += keys[(1 * 2 + 6) % 9];
				G5 += keys[(1 * 2 + 7) % 9] + tweaks[(1 * 2 + 2) % 3];
				G6 += keys[(1 * 2 + 8) % 9] + tweaks[(1 * 2 + 3) % 3];
				G7 += keys[(1 * 2 + 9) % 9] + 1 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// TWO
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 1) % 9];
				G1 += keys[(2 * 2 + 2) % 9];
				G2 += keys[(2 * 2 + 3) % 9];
				G3 += keys[(2 * 2 + 4) % 9];
				G4 += keys[(2 * 2 + 5) % 9];
				G5 += keys[(2 * 2 + 6) % 9] + tweaks[(2 * 2 + 1) % 3];
				G6 += keys[(2 * 2 + 7) % 9] + tweaks[(2 * 2 + 2) % 3];
				G7 += keys[(2 * 2 + 8) % 9] + 2 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 2) % 9];
				G1 += keys[(2 * 2 + 3) % 9];
				G2 += keys[(2 * 2 + 4) % 9];
				G3 += keys[(2 * 2 + 5) % 9];
				G4 += keys[(2 * 2 + 6) % 9];
				G5 += keys[(2 * 2 + 7) % 9] + tweaks[(2 * 2 + 2) % 3];
				G6 += keys[(2 * 2 + 8) % 9] + tweaks[(2 * 2 + 3) % 3];
				G7 += keys[(2 * 2 + 9) % 9] + 2 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// THBREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 1) % 9];
				G1 += keys[(3 * 2 + 2) % 9];
				G2 += keys[(3 * 2 + 3) % 9];
				G3 += keys[(3 * 2 + 4) % 9];
				G4 += keys[(3 * 2 + 5) % 9];
				G5 += keys[(3 * 2 + 6) % 9] + tweaks[(3 * 2 + 1) % 3];
				G6 += keys[(3 * 2 + 7) % 9] + tweaks[(3 * 2 + 2) % 3];
				G7 += keys[(3 * 2 + 8) % 9] + 3 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 2) % 9];
				G1 += keys[(3 * 2 + 3) % 9];
				G2 += keys[(3 * 2 + 4) % 9];
				G3 += keys[(3 * 2 + 5) % 9];
				G4 += keys[(3 * 2 + 6) % 9];
				G5 += keys[(3 * 2 + 7) % 9] + tweaks[(3 * 2 + 2) % 3];
				G6 += keys[(3 * 2 + 8) % 9] + tweaks[(3 * 2 + 3) % 3];
				G7 += keys[(3 * 2 + 9) % 9] + 3 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// FOUR
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 1) % 9];
				G1 += keys[(4 * 2 + 2) % 9];
				G2 += keys[(4 * 2 + 3) % 9];
				G3 += keys[(4 * 2 + 4) % 9];
				G4 += keys[(4 * 2 + 5) % 9];
				G5 += keys[(4 * 2 + 6) % 9] + tweaks[(4 * 2 + 1) % 3];
				G6 += keys[(4 * 2 + 7) % 9] + tweaks[(4 * 2 + 2) % 3];
				G7 += keys[(4 * 2 + 8) % 9] + 4 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 2) % 9];
				G1 += keys[(4 * 2 + 3) % 9];
				G2 += keys[(4 * 2 + 4) % 9];
				G3 += keys[(4 * 2 + 5) % 9];
				G4 += keys[(4 * 2 + 6) % 9];
				G5 += keys[(4 * 2 + 7) % 9] + tweaks[(4 * 2 + 2) % 3];
				G6 += keys[(4 * 2 + 8) % 9] + tweaks[(4 * 2 + 3) % 3];
				G7 += keys[(4 * 2 + 9) % 9] + 4 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// FIVE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 1) % 9];
				G1 += keys[(5 * 2 + 2) % 9];
				G2 += keys[(5 * 2 + 3) % 9];
				G3 += keys[(5 * 2 + 4) % 9];
				G4 += keys[(5 * 2 + 5) % 9];
				G5 += keys[(5 * 2 + 6) % 9] + tweaks[(5 * 2 + 1) % 3];
				G6 += keys[(5 * 2 + 7) % 9] + tweaks[(5 * 2 + 2) % 3];
				G7 += keys[(5 * 2 + 8) % 9] + 5 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 2) % 9];
				G1 += keys[(5 * 2 + 3) % 9];
				G2 += keys[(5 * 2 + 4) % 9];
				G3 += keys[(5 * 2 + 5) % 9];
				G4 += keys[(5 * 2 + 6) % 9];
				G5 += keys[(5 * 2 + 7) % 9] + tweaks[(5 * 2 + 2) % 3];
				G6 += keys[(5 * 2 + 8) % 9] + tweaks[(5 * 2 + 3) % 3];
				G7 += keys[(5 * 2 + 9) % 9] + 5 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// SIZ
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 1) % 9];
				G1 += keys[(6 * 2 + 2) % 9];
				G2 += keys[(6 * 2 + 3) % 9];
				G3 += keys[(6 * 2 + 4) % 9];
				G4 += keys[(6 * 2 + 5) % 9];
				G5 += keys[(6 * 2 + 6) % 9] + tweaks[(6 * 2 + 1) % 3];
				G6 += keys[(6 * 2 + 7) % 9] + tweaks[(6 * 2 + 2) % 3];
				G7 += keys[(6 * 2 + 8) % 9] + 6 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 2) % 9];
				G1 += keys[(6 * 2 + 3) % 9];
				G2 += keys[(6 * 2 + 4) % 9];
				G3 += keys[(6 * 2 + 5) % 9];
				G4 += keys[(6 * 2 + 6) % 9];
				G5 += keys[(6 * 2 + 7) % 9] + tweaks[(6 * 2 + 2) % 3];
				G6 += keys[(6 * 2 + 8) % 9] + tweaks[(6 * 2 + 3) % 3];
				G7 += keys[(6 * 2 + 9) % 9] + 6 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// DEVEN
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 1) % 9];
				G1 += keys[(7 * 2 + 2) % 9];
				G2 += keys[(7 * 2 + 3) % 9];
				G3 += keys[(7 * 2 + 4) % 9];
				G4 += keys[(7 * 2 + 5) % 9];
				G5 += keys[(7 * 2 + 6) % 9] + tweaks[(7 * 2 + 1) % 3];
				G6 += keys[(7 * 2 + 7) % 9] + tweaks[(7 * 2 + 2) % 3];
				G7 += keys[(7 * 2 + 8) % 9] + 7 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 2) % 9];
				G1 += keys[(7 * 2 + 3) % 9];
				G2 += keys[(7 * 2 + 4) % 9];
				G3 += keys[(7 * 2 + 5) % 9];
				G4 += keys[(7 * 2 + 6) % 9];
				G5 += keys[(7 * 2 + 7) % 9] + tweaks[(7 * 2 + 2) % 3];
				G6 += keys[(7 * 2 + 8) % 9] + tweaks[(7 * 2 + 3) % 3];
				G7 += keys[(7 * 2 + 9) % 9] + 7 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// EIGHT
				// DEVEN
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 46) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 36) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 19) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 37) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G2 += G1;
				G1 = _rotl64(G1, 33) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 27) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 14) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 42) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 17) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 49) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 36) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 39) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 44) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 9) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 54) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 56) ^ G4;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 4);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 1) % 9];
				G1 += keys[(8 * 2 + 2) % 9];
				G2 += keys[(8 * 2 + 3) % 9];
				G3 += keys[(8 * 2 + 4) % 9];
				G4 += keys[(8 * 2 + 5) % 9];
				G5 += keys[(8 * 2 + 6) % 9] + tweaks[(8 * 2 + 1) % 3];
				G6 += keys[(8 * 2 + 7) % 9] + tweaks[(8 * 2 + 2) % 3];
				G7 += keys[(8 * 2 + 8) % 9] + 8 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 1);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 39) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 30) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 34) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 24) ^ G6;

#ifdef DEBUG
				printf("round %d:\n", s * 8 + 5);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				G2 += G1;
				G1 = _rotl64(G1, 13) ^ G2;
				G4 += G7;
				G7 = _rotl64(G7, 50) ^ G4;
				G6 += G5;
				G5 = _rotl64(G5, 10) ^ G6;
				G0 += G3;
				G3 = _rotl64(G3, 17) ^ G0;

				G4 += G1;
				G1 = _rotl64(G1, 25) ^ G4;
				G6 += G3;
				G3 = _rotl64(G3, 29) ^ G6;
				G0 += G5;
				G5 = _rotl64(G5, 39) ^ G0;
				G2 += G7;
				G7 = _rotl64(G7, 43) ^ G2;

				G6 += G1;
				G1 = _rotl64(G1, 8) ^ G6;
				G0 += G7;
				G7 = _rotl64(G7, 35) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 56) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 22) ^ G4;


#ifdef DEBUG
				printf("round %d:\n", s * 8 + 8);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 2) % 9];
				G1 += keys[(8 * 2 + 3) % 9];
				G2 += keys[(8 * 2 + 4) % 9];
				G3 += keys[(8 * 2 + 5) % 9];
				G4 += keys[(8 * 2 + 6) % 9];
				G5 += keys[(8 * 2 + 7) % 9] + tweaks[(8 * 2 + 2) % 3];
				G6 += keys[(8 * 2 + 8) % 9] + tweaks[(8 * 2 + 3) % 3];
				G7 += keys[(8 * 2 + 9) % 9] + 8 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", s * 2 + 2);
				for (int i = 0; i < 8; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


//			}
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

		memcpy(hash, H, hashbitlen() / 8);
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
