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

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		serpent256* clone() const override { return new serpent256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	protected:
		bool do_init();

		uint32_t W[140];
	};

	class serpent128 : public serpent256
	{
	public:
		serpent128();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		serpent128* clone() const override { return new serpent128; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class serpent192 : public serpent256
	{
	public:
		serpent192();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 192; }
		serpent192* clone() const override { return new serpent192; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

}

#endif

