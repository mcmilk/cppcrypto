/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CAMELLIA_H
#define CPPCRYPTO_CAMELLIA_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class camellia128 : public block_cipher
	{
	public:
		camellia128();

		int blocksize() const { return 128; }
		int keysize() const { return 128; }
		block_cipher* clone() const { return new camellia128; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t ks[26];
	};

	class camellia256 : public block_cipher
	{
	public:
		camellia256();

		int blocksize() const { return 128; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new camellia256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t ks[34];
	};

	class camellia192 : public camellia256
	{
	public:
		int keysize() const { return 192; }
		block_cipher* clone() const { return new camellia192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

}

#endif