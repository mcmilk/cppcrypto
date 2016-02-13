/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SPECK_H
#define CPPCRYPTO_SPECK_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
	class speck128_128 : public block_cipher
	{
	public:
		~speck128_128();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new speck128_128; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[32];
	};

	class speck128_192 : public block_cipher
	{
	public:
		~speck128_192();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new speck128_192; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[33];
	};

	class speck128_256 : public block_cipher
	{
	public:
		~speck128_256();

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new speck128_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t W_[34];
	};

}

#endif

