/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/
//#define CPPCRYPTO_DEBUG

#include <memory.h>
#include "threefish.h"
#include "portability.h"

namespace cppcrypto
{
#define IG512(G0, G1, G2, G3, G4, G5, G6, G7, C0, C1, C2, C3) \
	G7 = rotater64(G7 ^ G6, C3); \
	G6 -= G7; \
	G5 = rotater64(G5 ^ G4, C2); \
	G4 -= G5; \
	G3 = rotater64(G3 ^ G2, C1); \
	G2 -= G3; \
	G1 = rotater64(G1 ^ G0, C0); \
	G0 -= G1;

#define G512(G0, G1, G2, G3, G4, G5, G6, G7, C0, C1, C2, C3) \
	G0 += G1; \
	G1 = rotatel64(G1, C0) ^ G0; \
	G2 += G3; \
	G3 = rotatel64(G3, C1) ^ G2; \
	G4 += G5; \
	G5 = rotatel64(G5, C2) ^ G4; \
	G6 += G7; \
	G7 = rotatel64(G7, C3) ^ G6;

#define IKS512(r) \
	G0 -= keys[(r + 1) % 9]; \
	G1 -= keys[(r + 2) % 9]; \
	G2 -= keys[(r + 3) % 9]; \
	G3 -= keys[(r + 4) % 9]; \
	G4 -= keys[(r + 5) % 9]; \
	G5 -= (keys[(r + 6) % 9] + tweaks[(r + 1) % 3]); \
	G6 -= (keys[(r + 7) % 9] + tweaks[(r + 2) % 3]); \
	G7 -= (keys[(r + 8) % 9] + r + 1);

#define KS512(r) \
	G0 += keys[(r + 1) % 9]; \
	G1 += keys[(r + 2) % 9]; \
	G2 += keys[(r + 3) % 9]; \
	G3 += keys[(r + 4) % 9]; \
	G4 += keys[(r + 5) % 9]; \
	G5 += keys[(r + 6) % 9] + tweaks[(r + 1) % 3]; \
	G6 += keys[(r + 7) % 9] + tweaks[(r + 2) % 3]; \
	G7 += keys[(r + 8) % 9] + r + 1;

#define IG8512(r) \
	IG512(G6, G1, G0, G7, G2, G5, G4, G3, 8, 35, 56, 22); \
	IG512(G4, G1, G6, G3, G0, G5, G2, G7, 25, 29, 39, 43); \
	IG512(G2, G1, G4, G7, G6, G5, G0, G3, 13, 50, 10, 17); \
    IG512(G0, G1, G2, G3, G4, G5, G6, G7, 39, 30, 34, 24); \
	IKS512(r) \
	IG512(G6, G1, G0, G7, G2, G5, G4, G3, 44, 9, 54, 56); \
	IG512(G4, G1, G6, G3, G0, G5, G2, G7, 17, 49, 36, 39); \
	IG512(G2, G1, G4, G7, G6, G5, G0, G3, 33, 27, 14, 42); \
	IG512(G0, G1, G2, G3, G4, G5, G6, G7, 46, 36, 19, 37); \
	IKS512(r - 1)

#define G8512(r) \
	G512(G0, G1, G2, G3, G4, G5, G6, G7, 46, 36, 19, 37); \
	G512(G2, G1, G4, G7, G6, G5, G0, G3, 33, 27, 14, 42); \
	G512(G4, G1, G6, G3, G0, G5, G2, G7, 17, 49, 36, 39); \
	G512(G6, G1, G0, G7, G2, G5, G4, G3, 44, 9, 54, 56); \
	KS512(r) \
    G512(G0, G1, G2, G3, G4, G5, G6, G7, 39, 30, 34, 24); \
	G512(G2, G1, G4, G7, G6, G5, G0, G3, 13, 50, 10, 17); \
	G512(G4, G1, G6, G3, G0, G5, G2, G7, 25, 29, 39, 43); \
	G512(G6, G1, G0, G7, G2, G5, G4, G3, 8, 35, 56, 22); \
	KS512(r + 1)

	bool threefish512_512::init(const unsigned char* key, block_cipher::direction direction)
	{
		memcpy(keys, key, 512 / 8);
		keys[8] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3] ^ keys[4] ^ keys[5] ^ keys[6] ^ keys[7];
		memset(tweaks, 0, sizeof(tweaks));
		
		return true;
	}

	void threefish512_512::set_tweak(const unsigned char* tweak)
	{
		memcpy(tweaks, tweak, 128 / 8);
		tweaks[2] = tweaks[0] ^ tweaks[1];
	}

	void threefish512_512::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t G0, G1, G2, G3, G4, G5, G6, G7;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) - keys[0];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) - keys[1];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) - keys[2];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) - keys[3];
		G4 = (reinterpret_cast<const uint64_t*>(in)[4]) - keys[4];
		G5 = (reinterpret_cast<const uint64_t*>(in)[5]) - keys[5];
		G6 = (reinterpret_cast<const uint64_t*>(in)[6]) - keys[6];
		G7 = (reinterpret_cast<const uint64_t*>(in)[7]) - keys[7];
		G5 -= tweaks[0];
		G6 -= tweaks[1];
		G7 -= 18;

		// The loop is fully unrolled for performance reasons
		IG8512(16);
		IG8512(14);
		IG8512(12);
		IG8512(10);
		IG8512(8);
		IG8512(6);
		IG8512(4);
		IG8512(2);
		IG8512(0);

		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
		reinterpret_cast<uint64_t*>(out)[4] = G4;
		reinterpret_cast<uint64_t*>(out)[5] = G5;
		reinterpret_cast<uint64_t*>(out)[6] = G6;
		reinterpret_cast<uint64_t*>(out)[7] = G7;
	}

	void threefish512_512::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t G0, G1, G2, G3, G4, G5, G6, G7;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) + keys[0];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) + keys[1];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) + keys[2];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) + keys[3];
		G4 = (reinterpret_cast<const uint64_t*>(in)[4]) + keys[4];
		G5 = (reinterpret_cast<const uint64_t*>(in)[5]) + keys[5];
		G6 = (reinterpret_cast<const uint64_t*>(in)[6]) + keys[6];
		G7 = (reinterpret_cast<const uint64_t*>(in)[7]) + keys[7];
		G5 += tweaks[0];
		G6 += tweaks[1];

		// The loop is fully unrolled for performance reasons
		G8512(0);
		G8512(2);
		G8512(4);
		G8512(6);
		G8512(8);
		G8512(10);
		G8512(12);
		G8512(14);
		G8512(16);
		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
		reinterpret_cast<uint64_t*>(out)[4] = G4;
		reinterpret_cast<uint64_t*>(out)[5] = G5;
		reinterpret_cast<uint64_t*>(out)[6] = G6;
		reinterpret_cast<uint64_t*>(out)[7] = G7;
	}

	threefish512_512::~threefish512_512()
	{
		clear();
	}

	void threefish512_512::clear()
	{
		zero_memory(keys, sizeof(keys));
		zero_memory(tweaks, sizeof(tweaks));
	}

#define IG1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, C1, C2, C3, C4, C5, C6, C7, C8) \
	G15 = rotater64(G15 ^ G14, C8); \
	G14 -= G15; \
	G13 = rotater64(G13 ^ G12, C7); \
	G12 -= G13; \
	G11 = rotater64(G11 ^ G10, C6); \
	G10 -= G11; \
	G9 = rotater64(G9 ^ G8, C5); \
	G8 -= G9; \
	G7 = rotater64(G7 ^ G6, C4); \
	G6 -= G7; \
	G5 = rotater64(G5 ^ G4, C3); \
	G4 -= G5; \
	G3 = rotater64(G3 ^ G2, C2); \
	G2 -= G3; \
	G1 = rotater64(G1 ^ G0, C1); \
	G0 -= G1;

#define G1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, C1, C2, C3, C4, C5, C6, C7, C8) \
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

#define IKS1024(r) \
	G0 -= keys[(r + 1) % 17]; \
	G1 -= keys[(r + 2) % 17]; \
	G2 -= keys[(r + 3) % 17]; \
	G3 -= keys[(r + 4) % 17]; \
	G4 -= keys[(r + 5) % 17]; \
	G5 -= keys[(r + 6) % 17]; \
	G6 -= keys[(r + 7) % 17]; \
	G7 -= keys[(r + 8) % 17]; \
	G8 -= keys[(r + 9) % 17]; \
	G9 -= keys[(r + 10) % 17]; \
	G10 -= keys[(r + 11) % 17]; \
	G11 -= keys[(r + 12) % 17]; \
	G12 -= keys[(r + 13) % 17]; \
	G13 -= (keys[(r + 14) % 17] + tweaks[(r + 1) % 3]); \
	G14 -= (keys[(r + 15) % 17] + tweaks[(r + 2) % 3]); \
	G15 -= (keys[(r + 16) % 17] + r + 1);

#define KS1024(r) \
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

#define IG81024(r) \
	IG1024(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 9, 48, 35, 52, 23, 31, 37, 20); \
	IG1024(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 31, 44, 47, 46, 19, 42, 44, 25); \
	IG1024(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 16, 34, 56, 51, 4, 53, 42, 41); \
	IG1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 41, 9, 37, 31, 12, 47, 44, 30); \
	IKS1024(r); \
	IG1024(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 5, 20, 48, 41, 47, 28, 16, 25); \
	IG1024(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 33, 4, 51, 13, 34, 41, 59, 17); \
	IG1024(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 38, 19, 10, 55, 49, 18, 23, 52); \
	IG1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 24, 13, 8, 47, 8, 17, 22, 37); \
	IKS1024(r - 1);

#define G81024(r) \
	G1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 24, 13, 8, 47, 8, 17, 22, 37); \
	G1024(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 38, 19, 10, 55, 49, 18, 23, 52); \
	G1024(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 33, 4, 51, 13, 34, 41, 59, 17); \
	G1024(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 5, 20, 48, 41, 47, 28, 16, 25); \
	KS1024(r); \
	G1024(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15, 41, 9, 37, 31, 12, 47, 44, 30); \
	G1024(G0, G9, G2, G13, G6, G11, G4, G15, G10, G7, G12, G3, G14, G5, G8, G1, 16, 34, 56, 51, 4, 53, 42, 41); \
	G1024(G0, G7, G2, G5, G4, G3, G6, G1, G12, G15, G14, G13, G8, G11, G10, G9, 31, 44, 47, 46, 19, 42, 44, 25); \
	G1024(G0, G15, G2, G11, G6, G13, G4, G9, G14, G1, G8, G5, G10, G3, G12, G7, 9, 48, 35, 52, 23, 31, 37, 20); \
	KS1024(r + 1);


	bool threefish1024_1024::init(const unsigned char* key, block_cipher::direction direction)
	{
		memcpy(keys, key, 1024 / 8);
		keys[16] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3] ^ keys[4] ^ keys[5] ^ keys[6] ^ keys[7]
			^ keys[8] ^ keys[9] ^ keys[10] ^ keys[11] ^ keys[12] ^ keys[13] ^ keys[14] ^ keys[15];
		memset(tweaks, 0, sizeof(tweaks));

		return true;
	}

	void threefish1024_1024::set_tweak(const unsigned char* tweak)
	{
		memcpy(tweaks, tweak, 128 / 8);
		tweaks[2] = tweaks[0] ^ tweaks[1];
	}

	void threefish1024_1024::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		// Making this an array results in a less efficient compiled code
		uint64_t G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) - keys[3];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) - keys[4];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) - keys[5];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) - keys[6];
		G4 = (reinterpret_cast<const uint64_t*>(in)[4]) - keys[7];
		G5 = (reinterpret_cast<const uint64_t*>(in)[5]) - keys[8];
		G6 = (reinterpret_cast<const uint64_t*>(in)[6]) - keys[9];
		G7 = (reinterpret_cast<const uint64_t*>(in)[7]) - keys[10];
		G8 = (reinterpret_cast<const uint64_t*>(in)[8]) - keys[11];
		G9 = (reinterpret_cast<const uint64_t*>(in)[9]) - keys[12];
		G10 = (reinterpret_cast<const uint64_t*>(in)[10]) - keys[13];
		G11 = (reinterpret_cast<const uint64_t*>(in)[11]) - keys[14];
		G12 = (reinterpret_cast<const uint64_t*>(in)[12]) - keys[15];
		G13 = (reinterpret_cast<const uint64_t*>(in)[13]) - keys[16];
		G14 = (reinterpret_cast<const uint64_t*>(in)[14]) - keys[0];
		G15 = (reinterpret_cast<const uint64_t*>(in)[15]) - keys[1];
		G13 -= tweaks[2];
		G14 -= tweaks[0];
		G15 -= 20;

		// The loop is fully unrolled for performance reasons
		IG81024(18);
		IG81024(16);
		IG81024(14);
		IG81024(12);
		IG81024(10);
		IG81024(8);
		IG81024(6);
		IG81024(4);
		IG81024(2);
		IG81024(0);
		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
		reinterpret_cast<uint64_t*>(out)[4] = G4;
		reinterpret_cast<uint64_t*>(out)[5] = G5;
		reinterpret_cast<uint64_t*>(out)[6] = G6;
		reinterpret_cast<uint64_t*>(out)[7] = G7;
		reinterpret_cast<uint64_t*>(out)[8] = G8;
		reinterpret_cast<uint64_t*>(out)[9] = G9;
		reinterpret_cast<uint64_t*>(out)[10] = G10;
		reinterpret_cast<uint64_t*>(out)[11] = G11;
		reinterpret_cast<uint64_t*>(out)[12] = G12;
		reinterpret_cast<uint64_t*>(out)[13] = G13;
		reinterpret_cast<uint64_t*>(out)[14] = G14;
		reinterpret_cast<uint64_t*>(out)[15] = G15;
	}

	void threefish1024_1024::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		// Making this an array results in a less efficient compiled code
		uint64_t G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12, G13, G14, G15;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) + keys[0];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) + keys[1];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) + keys[2];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) + keys[3];
		G4 = (reinterpret_cast<const uint64_t*>(in)[4]) + keys[4];
		G5 = (reinterpret_cast<const uint64_t*>(in)[5]) + keys[5];
		G6 = (reinterpret_cast<const uint64_t*>(in)[6]) + keys[6];
		G7 = (reinterpret_cast<const uint64_t*>(in)[7]) + keys[7];
		G8 = (reinterpret_cast<const uint64_t*>(in)[8]) + keys[8];
		G9 = (reinterpret_cast<const uint64_t*>(in)[9]) + keys[9];
		G10 = (reinterpret_cast<const uint64_t*>(in)[10]) + keys[10];
		G11 = (reinterpret_cast<const uint64_t*>(in)[11]) + keys[11];
		G12 = (reinterpret_cast<const uint64_t*>(in)[12]) + keys[12];
		G13 = (reinterpret_cast<const uint64_t*>(in)[13]) + keys[13];
		G14 = (reinterpret_cast<const uint64_t*>(in)[14]) + keys[14];
		G15 = (reinterpret_cast<const uint64_t*>(in)[15]) + keys[15];
		G13 += tweaks[0];
		G14 += tweaks[1];

		// The loop is fully unrolled for performance reasons
		G81024(0);
		G81024(2);
		G81024(4);
		G81024(6);
		G81024(8);
		G81024(10);
		G81024(12);
		G81024(14);
		G81024(16);
		G81024(18);
		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
		reinterpret_cast<uint64_t*>(out)[4] = G4;
		reinterpret_cast<uint64_t*>(out)[5] = G5;
		reinterpret_cast<uint64_t*>(out)[6] = G6;
		reinterpret_cast<uint64_t*>(out)[7] = G7;
		reinterpret_cast<uint64_t*>(out)[8] = G8;
		reinterpret_cast<uint64_t*>(out)[9] = G9;
		reinterpret_cast<uint64_t*>(out)[10] = G10;
		reinterpret_cast<uint64_t*>(out)[11] = G11;
		reinterpret_cast<uint64_t*>(out)[12] = G12;
		reinterpret_cast<uint64_t*>(out)[13] = G13;
		reinterpret_cast<uint64_t*>(out)[14] = G14;
		reinterpret_cast<uint64_t*>(out)[15] = G15;
	}

	threefish1024_1024::~threefish1024_1024()
	{
		clear();
	}

	void threefish1024_1024::clear()
	{
		zero_memory(keys, sizeof(keys));
		zero_memory(tweaks, sizeof(tweaks));
	}


#define G256(G0, G1, G2, G3, C0, C1) \
	G0 += G1; \
	G1 = rotatel64(G1, C0) ^ G0; \
	G2 += G3; \
	G3 = rotatel64(G3, C1) ^ G2;

#define IG256(G0, G1, G2, G3, C0, C1) \
	G3 = rotater64(G3 ^ G2, C1); \
	G2 -= G3; \
	G1 = rotater64(G1 ^ G0, C0); \
	G0 -= G1; \

#define KS256(r) \
	G0 += keys[(r + 1) % 5]; \
	G1 += keys[(r + 2) % 5] + tweaks[(r + 1) % 3]; \
	G2 += keys[(r + 3) % 5] + tweaks[(r + 2) % 3]; \
	G3 += keys[(r + 4) % 5] + r + 1;

#define IKS256(r) \
	G0 -= keys[(r + 1) % 5]; \
	G1 -= (keys[(r + 2) % 5] + tweaks[(r + 1) % 3]); \
	G2 -= (keys[(r + 3) % 5] + tweaks[(r + 2) % 3]); \
	G3 -= (keys[(r + 4) % 5] + r + 1);

#define G8256(r) \
	G256(G0, G1, G2, G3, 14, 16); \
	G256(G0, G3, G2, G1, 52, 57); \
	G256(G0, G1, G2, G3, 23, 40); \
	G256(G0, G3, G2, G1, 5, 37); \
	KS256(r); \
	G256(G0, G1, G2, G3, 25, 33); \
	G256(G0, G3, G2, G1, 46, 12); \
	G256(G0, G1, G2, G3, 58, 22); \
	G256(G0, G3, G2, G1, 32, 32); \
	KS256(r + 1);

#define IG8256(r) \
	IG256(G0, G3, G2, G1, 32, 32); \
	IG256(G0, G1, G2, G3, 58, 22); \
	IG256(G0, G3, G2, G1, 46, 12); \
	IG256(G0, G1, G2, G3, 25, 33); \
	IKS256(r); \
	IG256(G0, G3, G2, G1, 5, 37); \
	IG256(G0, G1, G2, G3, 23, 40); \
	IG256(G0, G3, G2, G1, 52, 57); \
	IG256(G0, G1, G2, G3, 14, 16); \
	IKS256(r - 1);

	bool threefish256_256::init(const unsigned char* key, block_cipher::direction direction)
	{
		memcpy(keys, key, 256 / 8);
		keys[4] = 0x1BD11BDAA9FC1A22ULL ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3];
		memset(tweaks, 0, sizeof(tweaks));

		return true;
	}

	void threefish256_256::set_tweak(const unsigned char* tweak)
	{
		memcpy(tweaks, tweak, 128 / 8);
		tweaks[2] = tweaks[0] ^ tweaks[1];
	}

	void threefish256_256::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		// Making this an array results in a less efficient compiled code
		uint64_t G0, G1, G2, G3;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) - keys[3];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) - keys[4];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) - keys[0];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) - keys[1];
		G1 -= tweaks[0];
		G2 -= tweaks[1];
		G3 -= 18;

		// The loop is fully unrolled for performance reasons
		IG8256(16);
		IG8256(14);
		IG8256(12);
		IG8256(10);
		IG8256(8);
		IG8256(6);
		IG8256(4);
		IG8256(2);
		IG8256(0);
		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
	}

	void threefish256_256::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		// Making this an array results in a less efficient compiled code
		uint64_t G0, G1, G2, G3;
		G0 = (reinterpret_cast<const uint64_t*>(in)[0]) + keys[0];
		G1 = (reinterpret_cast<const uint64_t*>(in)[1]) + keys[1];
		G2 = (reinterpret_cast<const uint64_t*>(in)[2]) + keys[2];
		G3 = (reinterpret_cast<const uint64_t*>(in)[3]) + keys[3];
		G1 += tweaks[0];
		G2 += tweaks[1];

		// The loop is fully unrolled for performance reasons
		G8256(0);
		G8256(2);
		G8256(4);
		G8256(6);
		G8256(8);
		G8256(10);
		G8256(12);
		G8256(14);
		G8256(16);
		reinterpret_cast<uint64_t*>(out)[0] = G0;
		reinterpret_cast<uint64_t*>(out)[1] = G1;
		reinterpret_cast<uint64_t*>(out)[2] = G2;
		reinterpret_cast<uint64_t*>(out)[3] = G3;
	}

	threefish256_256::~threefish256_256()
	{
		clear();
	}

	void threefish256_256::clear()
	{
		zero_memory(keys, sizeof(keys));
		zero_memory(tweaks, sizeof(tweaks));
	}


}
