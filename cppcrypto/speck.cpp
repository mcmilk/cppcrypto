/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "speck.h"
#include "portability.h"
#include <memory.h>
#include <bitset>

#ifdef _MSC_VER
#define inline __forceinline
#endif

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	speck128_128::~speck128_128()
	{
		clear();
	}

	void speck128_128::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	static inline void ks(uint64_t& x, uint64_t& y, uint64_t pk, uint64_t& nk, int i)
	{
		y = (pk + rotater64(x, 8)) ^ i;
		nk = rotatel64(pk, 3) ^ y;
	}

	bool speck128_128::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		uint64_t x = *(((const uint64_t*)key) + 1), y;

		ks(x, y, W_[0], W_[1], 0);
		ks(y, x, W_[1], W_[2], 1);
		ks(x, y, W_[2], W_[3], 2);
		ks(y, x, W_[3], W_[4], 3);
		ks(x, y, W_[4], W_[5], 4);
		ks(y, x, W_[5], W_[6], 5);
		ks(x, y, W_[6], W_[7], 6);
		ks(y, x, W_[7], W_[8], 7);
		ks(x, y, W_[8], W_[9], 8);
		ks(y, x, W_[9], W_[10], 9);
		ks(x, y, W_[10], W_[11], 10);
		ks(y, x, W_[11], W_[12], 11);
		ks(x, y, W_[12], W_[13], 12);
		ks(y, x, W_[13], W_[14], 13);
		ks(x, y, W_[14], W_[15], 14);
		ks(y, x, W_[15], W_[16], 15);
		ks(x, y, W_[16], W_[17], 16);
		ks(y, x, W_[17], W_[18], 17);
		ks(x, y, W_[18], W_[19], 18);
		ks(y, x, W_[19], W_[20], 19);
		ks(x, y, W_[20], W_[21], 20);
		ks(y, x, W_[21], W_[22], 21);
		ks(x, y, W_[22], W_[23], 22);
		ks(y, x, W_[23], W_[24], 23);
		ks(x, y, W_[24], W_[25], 24);
		ks(y, x, W_[25], W_[26], 25);
		ks(x, y, W_[26], W_[27], 26);
		ks(y, x, W_[27], W_[28], 27);
		ks(x, y, W_[28], W_[29], 28);
		ks(y, x, W_[29], W_[30], 29);
		ks(x, y, W_[30], W_[31], 30);

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 32; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	void speck128_128::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 32; i++)
		{
			x = rotater64(x, 8);
			x += y;
			x ^= W_[i];
			y = rotatel64(y, 3);
			y ^= x;
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}

	void speck128_128::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 31; i >= 0; i--)
		{
			y ^= x;
			y = rotater64(y, 3);
			x ^= W_[i];
			x -= y;
			x = rotatel64(x, 8);
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}


	speck128_192::~speck128_192()
	{
		clear();
	}

	void speck128_192::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	bool speck128_192::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		uint64_t l[34];
		memcpy(l, key+8, 16);

		for (int i = 0; i < 32; i++)
		{
			l[i + 2] = (W_[i] + rotater64(l[i], 8)) ^ i;
			W_[i + 1] = rotatel64(W_[i], 3) ^ l[i + 2];
		}

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 33; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	void speck128_192::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 33; i++)
		{
			x = rotater64(x, 8);
			x += y;
			x ^= W_[i];
			y = rotatel64(y, 3);
			y ^= x;
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}

	void speck128_192::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 32; i >= 0; i--)
		{
			y ^= x;
			y = rotater64(y, 3);
			x ^= W_[i];
			x -= y;
			x = rotatel64(x, 8);
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}


	speck128_256::~speck128_256()
	{
		clear();
	}

	void speck128_256::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	bool speck128_256::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		uint64_t l[36];
		memcpy(l, key + 8, 24);

		for (int i = 0; i < 33; i++)
		{
			l[i + 3] = (W_[i] + rotater64(l[i], 8)) ^ i;
			W_[i + 1] = rotatel64(W_[i], 3) ^ l[i + 3];
		}

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 34; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	void speck128_256::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 34; i++)
		{
			x = rotater64(x, 8);
			x += y;
			x ^= W_[i];
			y = rotatel64(y, 3);
			y ^= x;
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}

	void speck128_256::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 33; i >= 0; i--)
		{
			y ^= x;
			y = rotater64(y, 3);
			x ^= W_[i];
			x -= y;
			x = rotatel64(x, 8);
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}


}

