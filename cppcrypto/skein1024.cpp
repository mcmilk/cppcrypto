/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "cpuinfo.h"
#include "skein1024.h"

//#define DEBUG

namespace cppcrypto
{

	void skein1024_1024::update(const uint8_t* data, size_t len)
	{
		if (pos && pos + len > 128)
		{
			memcpy(m + pos, data, 128 - pos);
			transform(m, 1, 128);
			len -= 128 - pos;
			total += 128 - pos;
			data += 128 - pos;
			pos = 0;
		}
		if (len > 128)
		{
			size_t blocks = (len - 1) / 128;
			size_t bytes = blocks * 128;
			transform((void*)(data), blocks, 128);
			len -= bytes;
			total += (bytes)* 8;
			data += bytes;
		}
		memcpy(m, data, len);
		pos += len;
		total += len * 8;
	}

	void skein1024_1024::init()
	{
		tweak[0] = 0ULL;
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

		pos = 0;
		total = 0;
	};


	void skein1024_1024::transform(void* m, uint64_t num_blks, size_t reallen)
	{
		uint64_t keys[17];
		uint64_t tweaks[3];

		for (uint64_t b = 0; b < num_blks; b++)
		{
			uint64_t M[16];
			uint64_t G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15;
			for (uint64_t i = 0; i < 128 / 8; i++)
			{
				M[i] = (reinterpret_cast<const uint64_t*>(m)[b * 16 + i]);
			}

			memcpy(keys, H, sizeof(uint64_t)*16);
			memcpy(tweaks, tweak, sizeof(uint64_t)*2);
			tweaks[0] += reallen;
			tweaks[2] = tweaks[0] ^ tweaks[1];
			keys[16] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3] ^ keys[4] ^ keys[5] ^ keys[6] ^ keys[7]
				^ keys[8] ^ keys[9] ^ keys[10] ^ keys[11] ^ keys[12] ^ keys[13] ^ keys[14] ^ keys[15];

#ifdef DEBUG
			printf("transform; tweaks: ");
			for (int i = 0; i < 3; i++)
				printf("%llx ", tweaks[i]);
			printf("\nkeys:\n");
			for (int i = 0; i < 17; i++)
				printf("%llx ", keys[i]);
			printf("\n");
#endif

			//for (int i = 0; i < 16; i++)
			G0 = M[0] + keys[0];
			G1 = M[1] + keys[1];
			G2 = M[2] + keys[2];
			G3 = M[3] + keys[3];
			G4 = M[4] + keys[4];
			G5 = M[5] + keys[5];
			G6 = M[6] + keys[6];
			G7 = M[7] + keys[7];
			G8 = M[8] + keys[8];
			G9 = M[9] + keys[9];
			G10 = M[10] + keys[10];
			G11 = M[11] + keys[11];
			G12 = M[12] + keys[12];
			G13 = M[13] + keys[13];
			G14 = M[14] + keys[14];
			G15 = M[15] + keys[15];
			G13 += tweaks[0];
			G14 += tweaks[1];

#ifdef DEBUG
			printf("message:\n");
			for (int i = 0; i < 16; i++)
				printf("%llx ", M[i]);
			printf("\n");
#endif


#ifdef DEBUG
			printf("before rounds:\n");
			for (int i = 0; i < 16; i++)
				printf("%llx ", G[i]);
			printf("\n");
#endif

			// The loop is fully unrolled for performance reasons
			//for (int s = 0; s < 80 / 8; s++)
			{
				// ZERIO
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 1) % 17];
				G1 += keys[(0 * 2 + 2) % 17];
				G2 += keys[(0 * 2 + 3) % 17];
				G3 += keys[(0 * 2 + 4) % 17];
				G4 += keys[(0 * 2 + 5) % 17];
				G5 += keys[(0 * 2 + 6) % 17];
				G6 += keys[(0 * 2 + 7) % 17];
				G7 += keys[(0 * 2 + 8) % 17];
				G8 += keys[(0 * 2 + 9) % 17];
				G9 += keys[(0 * 2 + 10) % 17];
				G10 += keys[(0 * 2 + 11) % 17];
				G11 += keys[(0 * 2 + 12) % 17];
				G12 += keys[(0 * 2 + 13) % 17];
				G13 += keys[(0 * 2 + 14) % 17] + tweaks[(0 * 2 + 1) % 3];
				G14 += keys[(0 * 2 + 15) % 17] + tweaks[(0 * 2 + 2) % 3];
				G15 += keys[(0 * 2 + 16) % 17] + 0 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 0 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 0 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(0 * 2 + 2) % 17];
				G1 += keys[(0 * 2 + 3) % 17];
				G2 += keys[(0 * 2 + 4) % 17];
				G3 += keys[(0 * 2 + 5) % 17];
				G4 += keys[(0 * 2 + 6) % 17];
				G5 += keys[(0 * 2 + 7) % 17];
				G6 += keys[(0 * 2 + 8) % 17];
				G7 += keys[(0 * 2 + 9) % 17];
				G8 += keys[(0 * 2 + 10) % 17];
				G9 += keys[(0 * 2 + 11) % 17];
				G10 += keys[(0 * 2 + 12) % 17];
				G11 += keys[(0 * 2 + 13) % 17];
				G12 += keys[(0 * 2 + 14) % 17];
				G13 += keys[(0 * 2 + 15) % 17] + tweaks[(0 * 2 + 2) % 3];
				G14 += keys[(0 * 2 + 16) % 17] + tweaks[(0 * 2 + 3) % 3];
				G15 += keys[(0 * 2 + 17) % 17] + 0 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 0 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// ONE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 1) % 17];
				G1 += keys[(1 * 2 + 2) % 17];
				G2 += keys[(1 * 2 + 3) % 17];
				G3 += keys[(1 * 2 + 4) % 17];
				G4 += keys[(1 * 2 + 5) % 17];
				G5 += keys[(1 * 2 + 6) % 17];
				G6 += keys[(1 * 2 + 7) % 17];
				G7 += keys[(1 * 2 + 8) % 17];
				G8 += keys[(1 * 2 + 9) % 17];
				G9 += keys[(1 * 2 + 10) % 17];
				G10 += keys[(1 * 2 + 11) % 17];
				G11 += keys[(1 * 2 + 12) % 17];
				G12 += keys[(1 * 2 + 13) % 17];
				G13 += keys[(1 * 2 + 14) % 17] + tweaks[(1 * 2 + 1) % 3];
				G14 += keys[(1 * 2 + 15) % 17] + tweaks[(1 * 2 + 2) % 3];
				G15 += keys[(1 * 2 + 16) % 17] + 1 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 1 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 1 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(1 * 2 + 2) % 17];
				G1 += keys[(1 * 2 + 3) % 17];
				G2 += keys[(1 * 2 + 4) % 17];
				G3 += keys[(1 * 2 + 5) % 17];
				G4 += keys[(1 * 2 + 6) % 17];
				G5 += keys[(1 * 2 + 7) % 17];
				G6 += keys[(1 * 2 + 8) % 17];
				G7 += keys[(1 * 2 + 9) % 17];
				G8 += keys[(1 * 2 + 10) % 17];
				G9 += keys[(1 * 2 + 11) % 17];
				G10 += keys[(1 * 2 + 12) % 17];
				G11 += keys[(1 * 2 + 13) % 17];
				G12 += keys[(1 * 2 + 14) % 17];
				G13 += keys[(1 * 2 + 15) % 17] + tweaks[(1 * 2 + 2) % 3];
				G14 += keys[(1 * 2 + 16) % 17] + tweaks[(1 * 2 + 3) % 3];
				G15 += keys[(1 * 2 + 17) % 17] + 1 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 1 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// TWO
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 1) % 17];
				G1 += keys[(2 * 2 + 2) % 17];
				G2 += keys[(2 * 2 + 3) % 17];
				G3 += keys[(2 * 2 + 4) % 17];
				G4 += keys[(2 * 2 + 5) % 17];
				G5 += keys[(2 * 2 + 6) % 17];
				G6 += keys[(2 * 2 + 7) % 17];
				G7 += keys[(2 * 2 + 8) % 17];
				G8 += keys[(2 * 2 + 9) % 17];
				G9 += keys[(2 * 2 + 10) % 17];
				G10 += keys[(2 * 2 + 11) % 17];
				G11 += keys[(2 * 2 + 12) % 17];
				G12 += keys[(2 * 2 + 13) % 17];
				G13 += keys[(2 * 2 + 14) % 17] + tweaks[(2 * 2 + 1) % 3];
				G14 += keys[(2 * 2 + 15) % 17] + tweaks[(2 * 2 + 2) % 3];
				G15 += keys[(2 * 2 + 16) % 17] + 2 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 2 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 2 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(2 * 2 + 2) % 17];
				G1 += keys[(2 * 2 + 3) % 17];
				G2 += keys[(2 * 2 + 4) % 17];
				G3 += keys[(2 * 2 + 5) % 17];
				G4 += keys[(2 * 2 + 6) % 17];
				G5 += keys[(2 * 2 + 7) % 17];
				G6 += keys[(2 * 2 + 8) % 17];
				G7 += keys[(2 * 2 + 9) % 17];
				G8 += keys[(2 * 2 + 10) % 17];
				G9 += keys[(2 * 2 + 11) % 17];
				G10 += keys[(2 * 2 + 12) % 17];
				G11 += keys[(2 * 2 + 13) % 17];
				G12 += keys[(2 * 2 + 14) % 17];
				G13 += keys[(2 * 2 + 15) % 17] + tweaks[(2 * 2 + 2) % 3];
				G14 += keys[(2 * 2 + 16) % 17] + tweaks[(2 * 2 + 3) % 3];
				G15 += keys[(2 * 2 + 17) % 17] + 2 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 2 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// THREE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 1) % 17];
				G1 += keys[(3 * 2 + 2) % 17];
				G2 += keys[(3 * 2 + 3) % 17];
				G3 += keys[(3 * 2 + 4) % 17];
				G4 += keys[(3 * 2 + 5) % 17];
				G5 += keys[(3 * 2 + 6) % 17];
				G6 += keys[(3 * 2 + 7) % 17];
				G7 += keys[(3 * 2 + 8) % 17];
				G8 += keys[(3 * 2 + 9) % 17];
				G9 += keys[(3 * 2 + 10) % 17];
				G10 += keys[(3 * 2 + 11) % 17];
				G11 += keys[(3 * 2 + 12) % 17];
				G12 += keys[(3 * 2 + 13) % 17];
				G13 += keys[(3 * 2 + 14) % 17] + tweaks[(3 * 2 + 1) % 3];
				G14 += keys[(3 * 2 + 15) % 17] + tweaks[(3 * 2 + 2) % 3];
				G15 += keys[(3 * 2 + 16) % 17] + 3 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 3 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(3 * 2 + 2) % 17];
				G1 += keys[(3 * 2 + 3) % 17];
				G2 += keys[(3 * 2 + 4) % 17];
				G3 += keys[(3 * 2 + 5) % 17];
				G4 += keys[(3 * 2 + 6) % 17];
				G5 += keys[(3 * 2 + 7) % 17];
				G6 += keys[(3 * 2 + 8) % 17];
				G7 += keys[(3 * 2 + 9) % 17];
				G8 += keys[(3 * 2 + 10) % 17];
				G9 += keys[(3 * 2 + 11) % 17];
				G10 += keys[(3 * 2 + 12) % 17];
				G11 += keys[(3 * 2 + 13) % 17];
				G12 += keys[(3 * 2 + 14) % 17];
				G13 += keys[(3 * 2 + 15) % 17] + tweaks[(3 * 2 + 2) % 3];
				G14 += keys[(3 * 2 + 16) % 17] + tweaks[(3 * 2 + 3) % 3];
				G15 += keys[(3 * 2 + 17) % 17] + 3 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 3 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// FOUR
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 4 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 4 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 1) % 17];
				G1 += keys[(4 * 2 + 2) % 17];
				G2 += keys[(4 * 2 + 3) % 17];
				G3 += keys[(4 * 2 + 4) % 17];
				G4 += keys[(4 * 2 + 5) % 17];
				G5 += keys[(4 * 2 + 6) % 17];
				G6 += keys[(4 * 2 + 7) % 17];
				G7 += keys[(4 * 2 + 8) % 17];
				G8 += keys[(4 * 2 + 9) % 17];
				G9 += keys[(4 * 2 + 10) % 17];
				G10 += keys[(4 * 2 + 11) % 17];
				G11 += keys[(4 * 2 + 12) % 17];
				G12 += keys[(4 * 2 + 13) % 17];
				G13 += keys[(4 * 2 + 14) % 17] + tweaks[(4 * 2 + 1) % 3];
				G14 += keys[(4 * 2 + 15) % 17] + tweaks[(4 * 2 + 2) % 3];
				G15 += keys[(4 * 2 + 16) % 17] + 4 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 4 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 4 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 4 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(4 * 2 + 2) % 17];
				G1 += keys[(4 * 2 + 3) % 17];
				G2 += keys[(4 * 2 + 4) % 17];
				G3 += keys[(4 * 2 + 5) % 17];
				G4 += keys[(4 * 2 + 6) % 17];
				G5 += keys[(4 * 2 + 7) % 17];
				G6 += keys[(4 * 2 + 8) % 17];
				G7 += keys[(4 * 2 + 9) % 17];
				G8 += keys[(4 * 2 + 10) % 17];
				G9 += keys[(4 * 2 + 11) % 17];
				G10 += keys[(4 * 2 + 12) % 17];
				G11 += keys[(4 * 2 + 13) % 17];
				G12 += keys[(4 * 2 + 14) % 17];
				G13 += keys[(4 * 2 + 15) % 17] + tweaks[(4 * 2 + 2) % 3];
				G14 += keys[(4 * 2 + 16) % 17] + tweaks[(4 * 2 + 3) % 3];
				G15 += keys[(4 * 2 + 17) % 17] + 4 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 4 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// FIVE
					// four rounds
					G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 5 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 5 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 1) % 17];
				G1 += keys[(5 * 2 + 2) % 17];
				G2 += keys[(5 * 2 + 3) % 17];
				G3 += keys[(5 * 2 + 4) % 17];
				G4 += keys[(5 * 2 + 5) % 17];
				G5 += keys[(5 * 2 + 6) % 17];
				G6 += keys[(5 * 2 + 7) % 17];
				G7 += keys[(5 * 2 + 8) % 17];
				G8 += keys[(5 * 2 + 9) % 17];
				G9 += keys[(5 * 2 + 10) % 17];
				G10 += keys[(5 * 2 + 11) % 17];
				G11 += keys[(5 * 2 + 12) % 17];
				G12 += keys[(5 * 2 + 13) % 17];
				G13 += keys[(5 * 2 + 14) % 17] + tweaks[(5 * 2 + 1) % 3];
				G14 += keys[(5 * 2 + 15) % 17] + tweaks[(5 * 2 + 2) % 3];
				G15 += keys[(5 * 2 + 16) % 17] + 5 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 5 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 5 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 5 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(5 * 2 + 2) % 17];
				G1 += keys[(5 * 2 + 3) % 17];
				G2 += keys[(5 * 2 + 4) % 17];
				G3 += keys[(5 * 2 + 5) % 17];
				G4 += keys[(5 * 2 + 6) % 17];
				G5 += keys[(5 * 2 + 7) % 17];
				G6 += keys[(5 * 2 + 8) % 17];
				G7 += keys[(5 * 2 + 9) % 17];
				G8 += keys[(5 * 2 + 10) % 17];
				G9 += keys[(5 * 2 + 11) % 17];
				G10 += keys[(5 * 2 + 12) % 17];
				G11 += keys[(5 * 2 + 13) % 17];
				G12 += keys[(5 * 2 + 14) % 17];
				G13 += keys[(5 * 2 + 15) % 17] + tweaks[(5 * 2 + 2) % 3];
				G14 += keys[(5 * 2 + 16) % 17] + tweaks[(5 * 2 + 3) % 3];
				G15 += keys[(5 * 2 + 17) % 17] + 5 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 5 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


				// SI
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 6 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 6 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 1) % 17];
				G1 += keys[(6 * 2 + 2) % 17];
				G2 += keys[(6 * 2 + 3) % 17];
				G3 += keys[(6 * 2 + 4) % 17];
				G4 += keys[(6 * 2 + 5) % 17];
				G5 += keys[(6 * 2 + 6) % 17];
				G6 += keys[(6 * 2 + 7) % 17];
				G7 += keys[(6 * 2 + 8) % 17];
				G8 += keys[(6 * 2 + 9) % 17];
				G9 += keys[(6 * 2 + 10) % 17];
				G10 += keys[(6 * 2 + 11) % 17];
				G11 += keys[(6 * 2 + 12) % 17];
				G12 += keys[(6 * 2 + 13) % 17];
				G13 += keys[(6 * 2 + 14) % 17] + tweaks[(6 * 2 + 1) % 3];
				G14 += keys[(6 * 2 + 15) % 17] + tweaks[(6 * 2 + 2) % 3];
				G15 += keys[(6 * 2 + 16) % 17] + 6 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 6 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 6 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 6 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(6 * 2 + 2) % 17];
				G1 += keys[(6 * 2 + 3) % 17];
				G2 += keys[(6 * 2 + 4) % 17];
				G3 += keys[(6 * 2 + 5) % 17];
				G4 += keys[(6 * 2 + 6) % 17];
				G5 += keys[(6 * 2 + 7) % 17];
				G6 += keys[(6 * 2 + 8) % 17];
				G7 += keys[(6 * 2 + 9) % 17];
				G8 += keys[(6 * 2 + 10) % 17];
				G9 += keys[(6 * 2 + 11) % 17];
				G10 += keys[(6 * 2 + 12) % 17];
				G11 += keys[(6 * 2 + 13) % 17];
				G12 += keys[(6 * 2 + 14) % 17];
				G13 += keys[(6 * 2 + 15) % 17] + tweaks[(6 * 2 + 2) % 3];
				G14 += keys[(6 * 2 + 16) % 17] + tweaks[(6 * 2 + 3) % 3];
				G15 += keys[(6 * 2 + 17) % 17] + 6 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 6 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// SEVEN
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 7 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 7 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 1) % 17];
				G1 += keys[(7 * 2 + 2) % 17];
				G2 += keys[(7 * 2 + 3) % 17];
				G3 += keys[(7 * 2 + 4) % 17];
				G4 += keys[(7 * 2 + 5) % 17];
				G5 += keys[(7 * 2 + 6) % 17];
				G6 += keys[(7 * 2 + 7) % 17];
				G7 += keys[(7 * 2 + 8) % 17];
				G8 += keys[(7 * 2 + 9) % 17];
				G9 += keys[(7 * 2 + 10) % 17];
				G10 += keys[(7 * 2 + 11) % 17];
				G11 += keys[(7 * 2 + 12) % 17];
				G12 += keys[(7 * 2 + 13) % 17];
				G13 += keys[(7 * 2 + 14) % 17] + tweaks[(7 * 2 + 1) % 3];
				G14 += keys[(7 * 2 + 15) % 17] + tweaks[(7 * 2 + 2) % 3];
				G15 += keys[(7 * 2 + 16) % 17] + 7 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 7 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 7 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 7 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(7 * 2 + 2) % 17];
				G1 += keys[(7 * 2 + 3) % 17];
				G2 += keys[(7 * 2 + 4) % 17];
				G3 += keys[(7 * 2 + 5) % 17];
				G4 += keys[(7 * 2 + 6) % 17];
				G5 += keys[(7 * 2 + 7) % 17];
				G6 += keys[(7 * 2 + 8) % 17];
				G7 += keys[(7 * 2 + 9) % 17];
				G8 += keys[(7 * 2 + 10) % 17];
				G9 += keys[(7 * 2 + 11) % 17];
				G10 += keys[(7 * 2 + 12) % 17];
				G11 += keys[(7 * 2 + 13) % 17];
				G12 += keys[(7 * 2 + 14) % 17];
				G13 += keys[(7 * 2 + 15) % 17] + tweaks[(7 * 2 + 2) % 3];
				G14 += keys[(7 * 2 + 16) % 17] + tweaks[(7 * 2 + 3) % 3];
				G15 += keys[(7 * 2 + 17) % 17] + 7 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 7 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// EIGHT
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 8 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 8 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 1) % 17];
				G1 += keys[(8 * 2 + 2) % 17];
				G2 += keys[(8 * 2 + 3) % 17];
				G3 += keys[(8 * 2 + 4) % 17];
				G4 += keys[(8 * 2 + 5) % 17];
				G5 += keys[(8 * 2 + 6) % 17];
				G6 += keys[(8 * 2 + 7) % 17];
				G7 += keys[(8 * 2 + 8) % 17];
				G8 += keys[(8 * 2 + 9) % 17];
				G9 += keys[(8 * 2 + 10) % 17];
				G10 += keys[(8 * 2 + 11) % 17];
				G11 += keys[(8 * 2 + 12) % 17];
				G12 += keys[(8 * 2 + 13) % 17];
				G13 += keys[(8 * 2 + 14) % 17] + tweaks[(8 * 2 + 1) % 3];
				G14 += keys[(8 * 2 + 15) % 17] + tweaks[(8 * 2 + 2) % 3];
				G15 += keys[(8 * 2 + 16) % 17] + 8 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 8 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 8 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 8 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(8 * 2 + 2) % 17];
				G1 += keys[(8 * 2 + 3) % 17];
				G2 += keys[(8 * 2 + 4) % 17];
				G3 += keys[(8 * 2 + 5) % 17];
				G4 += keys[(8 * 2 + 6) % 17];
				G5 += keys[(8 * 2 + 7) % 17];
				G6 += keys[(8 * 2 + 8) % 17];
				G7 += keys[(8 * 2 + 9) % 17];
				G8 += keys[(8 * 2 + 10) % 17];
				G9 += keys[(8 * 2 + 11) % 17];
				G10 += keys[(8 * 2 + 12) % 17];
				G11 += keys[(8 * 2 + 13) % 17];
				G12 += keys[(8 * 2 + 14) % 17];
				G13 += keys[(8 * 2 + 15) % 17] + tweaks[(8 * 2 + 2) % 3];
				G14 += keys[(8 * 2 + 16) % 17] + tweaks[(8 * 2 + 3) % 3];
				G15 += keys[(8 * 2 + 17) % 17] + 8 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 8 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif



				// NINE
				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 24) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 13) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 8) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 47) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 8) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 17) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 22) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 37) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 9 * 8 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 38) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 19) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 10) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 55) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 49) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 18) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 23) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 52) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 33) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 4) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 51) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 13) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 34) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 41) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 59) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 17) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 5) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 20) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 48) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 41) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 47) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 28) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 16) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 25) ^ G12;

#ifdef DEBUG
				printf("round %d:\n", 9 * 8 + 4);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(9 * 2 + 1) % 17];
				G1 += keys[(9 * 2 + 2) % 17];
				G2 += keys[(9 * 2 + 3) % 17];
				G3 += keys[(9 * 2 + 4) % 17];
				G4 += keys[(9 * 2 + 5) % 17];
				G5 += keys[(9 * 2 + 6) % 17];
				G6 += keys[(9 * 2 + 7) % 17];
				G7 += keys[(9 * 2 + 8) % 17];
				G8 += keys[(9 * 2 + 9) % 17];
				G9 += keys[(9 * 2 + 10) % 17];
				G10 += keys[(9 * 2 + 11) % 17];
				G11 += keys[(9 * 2 + 12) % 17];
				G12 += keys[(9 * 2 + 13) % 17];
				G13 += keys[(9 * 2 + 14) % 17] + tweaks[(9 * 2 + 1) % 3];
				G14 += keys[(9 * 2 + 15) % 17] + tweaks[(9 * 2 + 2) % 3];
				G15 += keys[(9 * 2 + 16) % 17] + 9 * 2 + 1;

#ifdef DEBUG
				printf("key schedule %d:\n", 9 * 2 + 1);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// four rounds
				G0 += G1;
				G1 = _rotl64(G1, 41) ^ G0;
				G2 += G3;
				G3 = _rotl64(G3, 9) ^ G2;
				G4 += G5;
				G5 = _rotl64(G5, 37) ^ G4;
				G6 += G7;
				G7 = _rotl64(G7, 31) ^ G6;
				G8 += G9;
				G9 = _rotl64(G9, 12) ^ G8;
				G10 += G11;
				G11 = _rotl64(G11, 47) ^ G10;
				G12 += G13;
				G13 = _rotl64(G13, 44) ^ G12;
				G14 += G15;
				G15 = _rotl64(G15, 30) ^ G14;

#ifdef DEBUG
				printf("round %d:\n", 9 * 8 + 5);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				G0 += G9;
				G9 = _rotl64(G9, 16) ^ G0;
				G2 += G13;
				G13 = _rotl64(G13, 34) ^ G2;
				G6 += G11;
				G11 = _rotl64(G11, 56) ^ G6;
				G4 += G15;
				G15 = _rotl64(G15, 51) ^ G4;
				G10 += G7;
				G7 = _rotl64(G7, 4) ^ G10;
				G12 += G3;
				G3 = _rotl64(G3, 53) ^ G12;
				G14 += G5;
				G5 = _rotl64(G5, 42) ^ G14;
				G8 += G1;
				G1 = _rotl64(G1, 41) ^ G8;

				G0 += G7;
				G7 = _rotl64(G7, 31) ^ G0;
				G2 += G5;
				G5 = _rotl64(G5, 44) ^ G2;
				G4 += G3;
				G3 = _rotl64(G3, 47) ^ G4;
				G6 += G1;
				G1 = _rotl64(G1, 46) ^ G6;
				G12 += G15;
				G15 = _rotl64(G15, 19) ^ G12;
				G14 += G13;
				G13 = _rotl64(G13, 42) ^ G14;
				G8 += G11;
				G11 = _rotl64(G11, 44) ^ G8;
				G10 += G9;
				G9 = _rotl64(G9, 25) ^ G10;

				G0 += G15;
				G15 = _rotl64(G15, 9) ^ G0;
				G2 += G11;
				G11 = _rotl64(G11, 48) ^ G2;
				G6 += G13;
				G13 = _rotl64(G13, 35) ^ G6;
				G4 += G9;
				G9 = _rotl64(G9, 52) ^ G4;
				G14 += G1;
				G1 = _rotl64(G1, 23) ^ G14;
				G8 += G5;
				G5 = _rotl64(G5, 31) ^ G8;
				G10 += G3;
				G3 = _rotl64(G3, 37) ^ G10;
				G12 += G7;
				G7 = _rotl64(G7, 20) ^ G12;


#ifdef DEBUG
				printf("round %d:\n", 9 * 8 + 8);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif

				// key schedule
				G0 += keys[(9 * 2 + 2) % 17];
				G1 += keys[(9 * 2 + 3) % 17];
				G2 += keys[(9 * 2 + 4) % 17];
				G3 += keys[(9 * 2 + 5) % 17];
				G4 += keys[(9 * 2 + 6) % 17];
				G5 += keys[(9 * 2 + 7) % 17];
				G6 += keys[(9 * 2 + 8) % 17];
				G7 += keys[(9 * 2 + 9) % 17];
				G8 += keys[(9 * 2 + 10) % 17];
				G9 += keys[(9 * 2 + 11) % 17];
				G10 += keys[(9 * 2 + 12) % 17];
				G11 += keys[(9 * 2 + 13) % 17];
				G12 += keys[(9 * 2 + 14) % 17];
				G13 += keys[(9 * 2 + 15) % 17] + tweaks[(9 * 2 + 2) % 3];
				G14 += keys[(9 * 2 + 16) % 17] + tweaks[(9 * 2 + 3) % 3];
				G15 += keys[(9 * 2 + 17) % 17] + 9 * 2 + 2;

#ifdef DEBUG
				printf("key schedule %d:\n", 9 * 2 + 2);
				for (int i = 0; i < 16; i++)
					printf("%llx ", G[i]);
				printf("\n");
#endif


			}
			tweaks[1] &= ~(64ULL << 56);
			tweak[0] = tweaks[0];
			tweak[1] = tweaks[1];
			//for (int i = 0; i < 16; i++)
			//	H[i] = G[i] ^ M[i];
			H[0] = G0 ^ M[0];
			H[1] = G1 ^ M[1];
			H[2] = G2 ^ M[2];
			H[3] = G3 ^ M[3];
			H[4] = G4 ^ M[4];
			H[5] = G5 ^ M[5];
			H[6] = G6 ^ M[6];
			H[7] = G7 ^ M[7];
			H[8] = G8 ^ M[8];
			H[9] = G9 ^ M[9];
			H[10] = G10 ^ M[10];
			H[11] = G11 ^ M[11];
			H[12] = G12 ^ M[12];
			H[13] = G13 ^ M[13];
			H[14] = G14 ^ M[14];
			H[15] = G15 ^ M[15];

		}

	}

	void skein1024_1024::final(uint8_t* hash)
	{
		tweak[1] |= 1ULL << 63; // last block
		if (pos < 128)
			memset(m + pos, 0, 128 - pos);

		transform(m, 1, pos);

		// generate output
		tweak[0] = 0;
		tweak[1] = 255ULL << 56;
		memset(m, 0, 128);
		transform(m, 1, 8);

		memcpy(hash, H, hashbitlen() / 8);
	}


	void skein1024_512::init()
	{
		tweak[0] = 0ULL;
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

		pos = 0;
		total = 0;
	};

	void skein1024_384::init()
	{
		tweak[0] = 0ULL;
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

		pos = 0;
		total = 0;
	};

	skein1024_1024::skein1024_1024()
	{
		H = (uint64_t*)_aligned_malloc(sizeof(uint64_t) * 16, 32);
	}

	skein1024_1024::~skein1024_1024()
	{
		_aligned_free(H);
	}

}
