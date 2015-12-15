/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SERPENT_H
#define CPPCRYPTO_SERPENT_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class serpent256 : public block_cipher
	{
	public:
		serpent256();
		~serpent256();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new serpent256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	protected:
		bool do_init();

		uint32_t W[140];
	};

	class serpent128 : public serpent256
	{
	public:
		serpent128();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new serpent128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class serpent192 : public serpent256
	{
	public:
		serpent192();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new serpent192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

}

#endif

