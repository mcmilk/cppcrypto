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

		size_t blocksize() const { return 128; }
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new cast6_256; }
		void clear();

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encrypt_block(const uint8_t* in, uint8_t* out);
		void decrypt_block(const uint8_t* in, uint8_t* out);

	protected:
		uint8_t kr[48];
		uint32_t km[48];
	};

	class cast6_224 : public cast6_256
	{
	public:
		size_t keysize() const { return 224; }
		block_cipher* clone() const { return new cast6_224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class cast6_192 : public cast6_256
	{
	public:
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new cast6_192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class cast6_160 : public cast6_256
	{
	public:
		size_t keysize() const { return 160; }
		block_cipher* clone() const { return new cast6_160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class cast6_128 : public cast6_256
	{
	public:
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new cast6_128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};


}

#endif

