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

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		simon128_128* clone() const override { return new simon128_128; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[68];
	};

	class simon128_192 : public block_cipher
	{
	public:
		~simon128_192();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 192; }
		simon128_192* clone() const override { return new simon128_192; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[69];
	};

	class simon128_256 : public block_cipher
	{
	public:
		~simon128_256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		simon128_256* clone() const override { return new simon128_256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t W_[72];
	};

}

#endif

