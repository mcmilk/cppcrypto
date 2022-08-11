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

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		speck128_128* clone() const override { return new speck128_128; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[32];
	};

	class speck128_192 : public block_cipher
	{
	public:
		~speck128_192();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 192; }
		speck128_192* clone() const override { return new speck128_192; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[33];
	};

	class speck128_256 : public block_cipher
	{
	public:
		~speck128_256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		speck128_256* clone() const override { return new speck128_256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[34];
	};

}

#endif

