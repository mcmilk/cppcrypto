/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_THREEFISH_H
#define CPPCRYPTO_THREEFISH_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class tweakable_block_cipher : public block_cipher
	{
	public:
		virtual size_t tweaksize() const = 0;
		virtual void set_tweak(const unsigned char* tweak) = 0;
	};

	class threefish512_512 : public tweakable_block_cipher
	{
	public:
		~threefish512_512();

		size_t blocksize() const override { return 512; }
		size_t keysize() const override { return 512; }
		size_t tweaksize() const override { return 128; }
		threefish512_512* clone() const override { return new threefish512_512; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void set_tweak(const unsigned char* tweak) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t keys[9];
		uint64_t tweaks[3];

	};

	class threefish1024_1024 : public tweakable_block_cipher
	{
	public:
		~threefish1024_1024();

		size_t blocksize() const override { return 1024; }
		size_t keysize() const override { return 1024; }
		size_t tweaksize() const override { return 128; }
		threefish1024_1024* clone() const override { return new threefish1024_1024; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void set_tweak(const unsigned char* tweak) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t keys[17];
		uint64_t tweaks[3];

	};

	class threefish256_256 : public tweakable_block_cipher
	{
	public:
		~threefish256_256();

		size_t blocksize() const override { return 256; }
		size_t keysize() const override { return 256; }
		size_t tweaksize() const override { return 128; }
		threefish256_256* clone() const override { return new threefish256_256; }
		void clear() override;

		bool init(const unsigned char* key, block_cipher::direction direction) override;
		void set_tweak(const unsigned char* tweak) override;
		void encrypt_block(const unsigned char* in, unsigned char* out) override;
		void decrypt_block(const unsigned char* in, unsigned char* out) override;

	private:
		uint64_t keys[5];
		uint64_t tweaks[3];

	};


}

#endif

