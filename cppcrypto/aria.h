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
		~aria128();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		aria128* clone() const override { return new aria128; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t rk[13 * 4];
	};

	class aria256 : public block_cipher
	{
	public:
		~aria256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		aria256* clone() const override { return new aria256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t rk[17 * 4];
	};


	class aria192 : public block_cipher
	{
	public:
		~aria192();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 192; }
		aria192* clone() const override { return new aria192; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint32_t rk[15 * 4];
	};

}

#endif

