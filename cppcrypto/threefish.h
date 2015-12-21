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
		virtual void set_tweak(const uint8_t* tweak) = 0;
	};

	class threefish512_512 : public tweakable_block_cipher
	{
	public:
		size_t blocksize() const { return 512; }
		size_t keysize() const { return 512; }
		size_t tweaksize() const { return 128; }
		block_cipher* clone() const { return new threefish512_512; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void set_tweak(const uint8_t* tweak);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t keys[9];
		uint64_t tweaks[3];

	};

	class threefish1024_1024 : public tweakable_block_cipher
	{
	public:
		size_t blocksize() const { return 1024; }
		size_t keysize() const { return 1024; }
		size_t tweaksize() const { return 128; }
		block_cipher* clone() const { return new threefish1024_1024; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void set_tweak(const uint8_t* tweak);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t keys[17];
		uint64_t tweaks[3];

	};

	class threefish256_256 : public tweakable_block_cipher
	{
	public:
		size_t blocksize() const { return 256; }
		size_t keysize() const { return 256; }
		size_t tweaksize() const { return 128; }
		block_cipher* clone() const { return new threefish256_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void set_tweak(const uint8_t* tweak);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t keys[5];
		uint64_t tweaks[3];

	};


}

#endif

