/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CAST6_H
#define CPPCRYPTO_CAST6_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class cast6_256 : public block_cipher
	{
	public:
		~cast6_256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		cast6_256* clone() const override { return new cast6_256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	protected:
		unsigned char kr[48];
		uint32_t km[48];
	};

	class cast6_224 : public cast6_256
	{
	public:
		size_t keysize() const override { return 224; }
		cast6_224* clone() const override { return new cast6_224; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class cast6_192 : public cast6_256
	{
	public:
		size_t keysize() const override { return 192; }
		cast6_192* clone() const override { return new cast6_192; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class cast6_160 : public cast6_256
	{
	public:
		size_t keysize() const override { return 160; }
		cast6_160* clone() const override { return new cast6_160; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};

	class cast6_128 : public cast6_256
	{
	public:
		size_t keysize() const override { return 128; }
		cast6_128* clone() const override { return new cast6_128; }

		bool init(const unsigned char* key, block_cipher::direction direction) override;
	};


}

#endif

