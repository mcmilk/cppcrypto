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
		~camellia128();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		camellia128* clone() const override { return new camellia128; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t ks[26];
	};

	class camellia256 : public block_cipher
	{
	public:
		camellia256();
		~camellia256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		camellia256* clone() const override { return new camellia256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t ks[34];
	};

	class camellia192 : public camellia256
	{
	public:
		size_t keysize() const override { return 192; }
		camellia192* clone() const override { return new camellia192; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

}

#endif

