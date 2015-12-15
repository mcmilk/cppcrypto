/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ARIA_H
#define CPPCRYPTO_ARIA_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class aria128 : public block_cipher
	{
	public:
		size_t blocksize() const { return 128; }
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new aria128; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint32_t rk[13 * 4];
	};

	class aria256 : public block_cipher
	{
	public:
		size_t blocksize() const { return 128; }
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new aria256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint32_t rk[17 * 4];
	};


	class aria192 : public block_cipher
	{
	public:
		size_t blocksize() const { return 128; }
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new aria192; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint32_t rk[15 * 4];
	};

}

#endif

