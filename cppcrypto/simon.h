/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SIMON_H
#define CPPCRYPTO_SIMON_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
	class simon128_128 : public block_cipher
	{
	public:
		~simon128_128();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new simon128_128; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[68];
	};

	class simon128_192 : public block_cipher
	{
	public:
		~simon128_192();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new simon128_192; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[69];
	};

	class simon128_256 : public block_cipher
	{
	public:
		~simon128_256();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new simon128_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[72];
	};

}

#endif

