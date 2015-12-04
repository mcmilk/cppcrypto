/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KALYNA_H
#define CPPCRYPTO_KALYNA_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class kalyna512_512 : public block_cipher
	{
	public:
		int blocksize() const { return 512; }
		int keysize() const { return 512; }
		block_cipher* clone() const { return new kalyna512_512; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t rk[19 * 8];
	};

	class kalyna256_512 : public block_cipher
	{
	public:
		int blocksize() const { return 256; }
		int keysize() const { return 512; }
		block_cipher* clone() const { return new kalyna256_512; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t rk[19 * 4];
	};

	class kalyna256_256 : public block_cipher
	{
	public:
		int blocksize() const { return 256; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new kalyna256_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t rk[15 * 4];
	};

	class kalyna128_256 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new kalyna128_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t rk[15 * 2];
	};

	class kalyna128_128 : public block_cipher
	{
	public:
		int blocksize() const { return 128; }
		int keysize() const { return 128; }
		block_cipher* clone() const { return new kalyna128_128; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	private:
		uint64_t rk[11 * 2];
	};


}

#endif