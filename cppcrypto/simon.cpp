/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "simon.h"
#include "portability.h"
#include <memory.h>
#include <bitset>

#ifdef _MSC_VER
#define inline __forceinline
#endif

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	simon128_128::~simon128_128()
	{
		clear();
	}

	void simon128_128::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	static inline uint64_t ks(uint64_t prev, uint64_t pprev, unsigned char z)
	{
		uint64_t tmp = rotater64(prev, 3);
		tmp = tmp ^ rotater64(tmp, 1);
		return 0xfffffffffffffffc ^ pprev ^ z ^ tmp;
	}

	bool simon128_128::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		W_[1] = *(((const uint64_t*)key) + 1);
		W_[2] = ks(W_[1], W_[0], 1);
		W_[3] = ks(W_[2], W_[1], 0);
		W_[4] = ks(W_[3], W_[2], 1);
		W_[5] = ks(W_[4], W_[3], 0);
		W_[6] = ks(W_[5], W_[4], 1);
		W_[7] = ks(W_[6], W_[5], 1);
		W_[8] = ks(W_[7], W_[6], 1);
		W_[9] = ks(W_[8], W_[7], 1);
		W_[10] = ks(W_[9], W_[8], 0);
		W_[11] = ks(W_[10], W_[9], 1);
		W_[12] = ks(W_[11], W_[10], 1);
		W_[13] = ks(W_[12], W_[11], 1);
		W_[14] = ks(W_[13], W_[12], 0);
		W_[15] = ks(W_[14], W_[13], 0);
		W_[16] = ks(W_[15], W_[14], 0);
		W_[17] = ks(W_[16], W_[15], 0);
		W_[18] = ks(W_[17], W_[16], 0);
		W_[19] = ks(W_[18], W_[17], 0);
		W_[20] = ks(W_[19], W_[18], 1);
		W_[21] = ks(W_[20], W_[19], 1);
		W_[22] = ks(W_[21], W_[20], 0);
		W_[23] = ks(W_[22], W_[21], 1);
		W_[24] = ks(W_[23], W_[22], 0);
		W_[25] = ks(W_[24], W_[23], 0);
		W_[26] = ks(W_[25], W_[24], 1);
		W_[27] = ks(W_[26], W_[25], 0);
		W_[28] = ks(W_[27], W_[26], 0);
		W_[29] = ks(W_[28], W_[27], 1);
		W_[30] = ks(W_[29], W_[28], 1);
		W_[31] = ks(W_[30], W_[29], 0);
		W_[32] = ks(W_[31], W_[30], 0);
		W_[33] = ks(W_[32], W_[31], 0);
		W_[34] = ks(W_[33], W_[32], 1);
		W_[35] = ks(W_[34], W_[33], 0);
		W_[36] = ks(W_[35], W_[34], 1);
		W_[37] = ks(W_[36], W_[35], 0);
		W_[38] = ks(W_[37], W_[36], 0);
		W_[39] = ks(W_[38], W_[37], 0);
		W_[40] = ks(W_[39], W_[38], 0);
		W_[41] = ks(W_[40], W_[39], 1);
		W_[42] = ks(W_[41], W_[40], 0);
		W_[43] = ks(W_[42], W_[41], 0);
		W_[44] = ks(W_[43], W_[42], 0);
		W_[45] = ks(W_[44], W_[43], 1);
		W_[46] = ks(W_[45], W_[44], 1);
		W_[47] = ks(W_[46], W_[45], 1);
		W_[48] = ks(W_[47], W_[46], 1);
		W_[49] = ks(W_[48], W_[47], 1);
		W_[50] = ks(W_[49], W_[48], 1);
		W_[51] = ks(W_[50], W_[49], 0);
		W_[52] = ks(W_[51], W_[50], 0);
		W_[53] = ks(W_[52], W_[51], 1);
		W_[54] = ks(W_[53], W_[52], 0);
		W_[55] = ks(W_[54], W_[53], 1);
		W_[56] = ks(W_[55], W_[54], 1);
		W_[57] = ks(W_[56], W_[55], 0);
		W_[58] = ks(W_[57], W_[56], 1);
		W_[59] = ks(W_[58], W_[57], 1);
		W_[60] = ks(W_[59], W_[58], 0);
		W_[61] = ks(W_[60], W_[59], 0);
		W_[62] = ks(W_[61], W_[60], 1);
		W_[63] = ks(W_[62], W_[61], 1);
		W_[64] = ks(W_[63], W_[62], 1);
		W_[65] = ks(W_[64], W_[63], 0);
		W_[66] = ks(W_[65], W_[64], 1);
		W_[67] = ks(W_[66], W_[65], 0);

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 68; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	inline static uint64_t f(uint64_t x)
	{
		return (rotatel64(x, 1) & rotatel64(x, 8)) ^ rotatel64(x, 2);
	}

	void simon128_128::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 68; i += 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i + 1];
		}
		
		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}

	void simon128_128::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 0);
		uint64_t y = *(((const uint64_t*)in) + 1);

		for (int i = 67; i > 0; i -= 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i - 1];
		}

		*(((uint64_t*)out) + 0) = x;
		*(((uint64_t*)out) + 1) = y;
	}


	simon128_192::~simon128_192()
	{
		clear();
	}

	void simon128_192::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	bool simon128_192::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		W_[1] = *(((const uint64_t*)key) + 1);
		W_[2] = *(((const uint64_t*)key) + 2);
		W_[3] = ks(W_[2], W_[0], 1);
		W_[4] = ks(W_[3], W_[1], 1);
		W_[5] = ks(W_[4], W_[2], 0);
		W_[6] = ks(W_[5], W_[3], 1);
		W_[7] = ks(W_[6], W_[4], 1);
		W_[8] = ks(W_[7], W_[5], 0);
		W_[9] = ks(W_[8], W_[6], 1);
		W_[10] = ks(W_[9], W_[7], 1);
		W_[11] = ks(W_[10], W_[8], 1);
		W_[12] = ks(W_[11], W_[9], 0);
		W_[13] = ks(W_[12], W_[10], 1);
		W_[14] = ks(W_[13], W_[11], 0);
		W_[15] = ks(W_[14], W_[12], 1);
		W_[16] = ks(W_[15], W_[13], 1);
		W_[17] = ks(W_[16], W_[14], 0);
		W_[18] = ks(W_[17], W_[15], 0);
		W_[19] = ks(W_[18], W_[16], 0);
		W_[20] = ks(W_[19], W_[17], 1);
		W_[21] = ks(W_[20], W_[18], 1);
		W_[22] = ks(W_[21], W_[19], 0);
		W_[23] = ks(W_[22], W_[20], 0);
		W_[24] = ks(W_[23], W_[21], 1);
		W_[25] = ks(W_[24], W_[22], 0);
		W_[26] = ks(W_[25], W_[23], 1);
		W_[27] = ks(W_[26], W_[24], 1);
		W_[28] = ks(W_[27], W_[25], 1);
		W_[29] = ks(W_[28], W_[26], 1);
		W_[30] = ks(W_[29], W_[27], 0);
		W_[31] = ks(W_[30], W_[28], 0);
		W_[32] = ks(W_[31], W_[29], 0);
		W_[33] = ks(W_[32], W_[30], 0);
		W_[34] = ks(W_[33], W_[31], 0);
		W_[35] = ks(W_[34], W_[32], 0);
		W_[36] = ks(W_[35], W_[33], 1);
		W_[37] = ks(W_[36], W_[34], 0);
		W_[38] = ks(W_[37], W_[35], 0);
		W_[39] = ks(W_[38], W_[36], 1);
		W_[40] = ks(W_[39], W_[37], 0);
		W_[41] = ks(W_[40], W_[38], 0);
		W_[42] = ks(W_[41], W_[39], 0);
		W_[43] = ks(W_[42], W_[40], 1);
		W_[44] = ks(W_[43], W_[41], 0);
		W_[45] = ks(W_[44], W_[42], 1);
		W_[46] = ks(W_[45], W_[43], 0);
		W_[47] = ks(W_[46], W_[44], 0);
		W_[48] = ks(W_[47], W_[45], 1);
		W_[49] = ks(W_[48], W_[46], 1);
		W_[50] = ks(W_[49], W_[47], 1);
		W_[51] = ks(W_[50], W_[48], 0);
		W_[52] = ks(W_[51], W_[49], 0);
		W_[53] = ks(W_[52], W_[50], 1);
		W_[54] = ks(W_[53], W_[51], 1);
		W_[55] = ks(W_[54], W_[52], 0);
		W_[56] = ks(W_[55], W_[53], 1);
		W_[57] = ks(W_[56], W_[54], 0);
		W_[58] = ks(W_[57], W_[55], 0);
		W_[59] = ks(W_[58], W_[56], 0);
		W_[60] = ks(W_[59], W_[57], 0);
		W_[61] = ks(W_[60], W_[58], 1);
		W_[62] = ks(W_[61], W_[59], 1);
		W_[63] = ks(W_[62], W_[60], 1);
		W_[64] = ks(W_[63], W_[61], 1);
		W_[65] = ks(W_[64], W_[62], 1);
		W_[66] = ks(W_[65], W_[63], 1);
		W_[67] = ks(W_[66], W_[64], 0);
		W_[68] = ks(W_[67], W_[65], 1);

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 69; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	void simon128_192::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 68; i += 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i + 1];
		}

		y ^= f(x);
		y ^= W_[68];

		*(((uint64_t*)out) + 0) = x;
		*(((uint64_t*)out) + 1) = y;
	}

	void simon128_192::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 0);
		uint64_t y = *(((const uint64_t*)in) + 1);

		for (int i = 68; i > 0; i -= 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i - 1];
		}

		y ^= f(x);
		y ^= W_[0];

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}


	simon128_256::~simon128_256()
	{
		clear();
	}

	void simon128_256::clear()
	{
		zero_memory(W_, sizeof(W_));
	}

	static inline uint64_t ks(uint64_t iplus3, uint64_t i, uint64_t iplus1, unsigned char z)
	{
		uint64_t tmp = rotater64(iplus3, 3) ^ iplus1;
		tmp = tmp ^ rotater64(tmp, 1);
		return 0xfffffffffffffffc ^ i ^ z ^ tmp;
	}

	bool simon128_256::init(const unsigned char* key, block_cipher::direction direction)
	{
		W_[0] = *(((const uint64_t*)key) + 0);
		W_[1] = *(((const uint64_t*)key) + 1);
		W_[2] = *(((const uint64_t*)key) + 2);
		W_[3] = *(((const uint64_t*)key) + 3);
		W_[4] = ks(W_[3], W_[0], W_[1], 1);
		W_[5] = ks(W_[4], W_[1], W_[2], 1);
		W_[6] = ks(W_[5], W_[2], W_[3], 0);
		W_[7] = ks(W_[6], W_[3], W_[4], 1);
		W_[8] = ks(W_[7], W_[4], W_[5], 0);
		W_[9] = ks(W_[8], W_[5], W_[6], 0);
		W_[10] = ks(W_[9], W_[6], W_[7], 0);
		W_[11] = ks(W_[10], W_[7], W_[8], 1);
		W_[12] = ks(W_[11], W_[8], W_[9], 1);
		W_[13] = ks(W_[12], W_[9], W_[10], 1);
		W_[14] = ks(W_[13], W_[10], W_[11], 1);
		W_[15] = ks(W_[14], W_[11], W_[12], 0);
		W_[16] = ks(W_[15], W_[12], W_[13], 0);
		W_[17] = ks(W_[16], W_[13], W_[14], 1);
		W_[18] = ks(W_[17], W_[14], W_[15], 1);
		W_[19] = ks(W_[18], W_[15], W_[16], 0);
		W_[20] = ks(W_[19], W_[16], W_[17], 1);
		W_[21] = ks(W_[20], W_[17], W_[18], 0);
		W_[22] = ks(W_[21], W_[18], W_[19], 1);
		W_[23] = ks(W_[22], W_[19], W_[20], 1);
		W_[24] = ks(W_[23], W_[20], W_[21], 0);
		W_[25] = ks(W_[24], W_[21], W_[22], 1);
		W_[26] = ks(W_[25], W_[22], W_[23], 1);
		W_[27] = ks(W_[26], W_[23], W_[24], 0);
		W_[28] = ks(W_[27], W_[24], W_[25], 0);
		W_[29] = ks(W_[28], W_[25], W_[26], 0);
		W_[30] = ks(W_[29], W_[26], W_[27], 1);
		W_[31] = ks(W_[30], W_[27], W_[28], 0);
		W_[32] = ks(W_[31], W_[28], W_[29], 0);
		W_[33] = ks(W_[32], W_[29], W_[30], 0);
		W_[34] = ks(W_[33], W_[30], W_[31], 0);
		W_[35] = ks(W_[34], W_[31], W_[32], 0);
		W_[36] = ks(W_[35], W_[32], W_[33], 0);
		W_[37] = ks(W_[36], W_[33], W_[34], 1);
		W_[38] = ks(W_[37], W_[34], W_[35], 0);
		W_[39] = ks(W_[38], W_[35], W_[36], 1);
		W_[40] = ks(W_[39], W_[36], W_[37], 1);
		W_[41] = ks(W_[40], W_[37], W_[38], 1);
		W_[42] = ks(W_[41], W_[38], W_[39], 0);
		W_[43] = ks(W_[42], W_[39], W_[40], 0);
		W_[44] = ks(W_[43], W_[40], W_[41], 0);
		W_[45] = ks(W_[44], W_[41], W_[42], 0);
		W_[46] = ks(W_[45], W_[42], W_[43], 1);
		W_[47] = ks(W_[46], W_[43], W_[44], 1);
		W_[48] = ks(W_[47], W_[44], W_[45], 0);
		W_[49] = ks(W_[48], W_[45], W_[46], 0);
		W_[50] = ks(W_[49], W_[46], W_[47], 1);
		W_[51] = ks(W_[50], W_[47], W_[48], 0);
		W_[52] = ks(W_[51], W_[48], W_[49], 1);
		W_[53] = ks(W_[52], W_[49], W_[50], 0);
		W_[54] = ks(W_[53], W_[50], W_[51], 0);
		W_[55] = ks(W_[54], W_[51], W_[52], 1);
		W_[56] = ks(W_[55], W_[52], W_[53], 0);
		W_[57] = ks(W_[56], W_[53], W_[54], 0);
		W_[58] = ks(W_[57], W_[54], W_[55], 1);
		W_[59] = ks(W_[58], W_[55], W_[56], 1);
		W_[60] = ks(W_[59], W_[56], W_[57], 1);
		W_[61] = ks(W_[60], W_[57], W_[58], 0);
		W_[62] = ks(W_[61], W_[58], W_[59], 1);
		W_[63] = ks(W_[62], W_[59], W_[60], 1);
		W_[64] = ks(W_[63], W_[60], W_[61], 1);
		W_[65] = ks(W_[64], W_[61], W_[62], 1);
		W_[66] = ks(W_[65], W_[62], W_[63], 1);
		W_[67] = ks(W_[66], W_[63], W_[64], 1);
		W_[68] = ks(W_[67], W_[64], W_[65], 0);
		W_[69] = ks(W_[68], W_[65], W_[66], 1);
		W_[70] = ks(W_[69], W_[66], W_[67], 0);
		W_[71] = ks(W_[70], W_[67], W_[68], 0);

#ifdef CPPCRYPTO_DEBUG
		for (int i = 0; i < 72; i++)
			printf("W_[%d]: %016llx\n", i, W_[i]);
#endif

		return true;
	}

	void simon128_256::encrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 1);
		uint64_t y = *(((const uint64_t*)in) + 0);

		for (int i = 0; i < 72; i += 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i + 1];
		}

		*(((uint64_t*)out) + 0) = y;
		*(((uint64_t*)out) + 1) = x;
	}

	void simon128_256::decrypt_block(const unsigned char* in, unsigned char* out)
	{
		uint64_t x = *(((const uint64_t*)in) + 0);
		uint64_t y = *(((const uint64_t*)in) + 1);

		for (int i = 71; i > 0; i -= 2)
		{
			y ^= f(x);
			y ^= W_[i];
			x ^= f(y);
			x ^= W_[i - 1];
		}

		*(((uint64_t*)out) + 0) = x;
		*(((uint64_t*)out) + 1) = y;
	}


}

