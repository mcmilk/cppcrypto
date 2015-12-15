/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SM4_H
#define CPPCRYPTO_SM4_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class sm4 : public block_cipher
	{
	public:
		size_t blocksize() const { return 128; }
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new sm4; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint32_t rk[32];
	};

}

#endif
