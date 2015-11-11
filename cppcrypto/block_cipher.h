/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_BLOCK_CIPHER_H
#define CPPCRYPTO_BLOCK_CIPHER_H

#include <stdint.h>
#include <string>

namespace cppcrypto
{

	class block_cipher
	{
	public:
		enum direction { encryption, decryption };

		virtual ~block_cipher() {}

		virtual int blocksize() const = 0;
		virtual int keysize() const = 0;
		virtual block_cipher* clone() const = 0;

		virtual bool init(const uint8_t* key, block_cipher::direction direction) = 0;
		virtual void encrypt_block(const uint8_t* in, uint8_t* out) = 0;
		virtual void decrypt_block(const uint8_t* in, uint8_t* out) = 0;

		virtual void encrypt_blocks(const uint8_t* in, uint8_t* out, size_t n);
		virtual void decrypt_blocks(const uint8_t* in, uint8_t* out, size_t n);
	};


}

#endif
