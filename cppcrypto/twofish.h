/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_TWOFISH_H
#define CPPCRYPTO_TWOFISH_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	namespace detail
	{
		class twofish : public block_cipher
		{
		public:
			size_t blocksize() const { return 128; }
			void encrypt_block(const uint8_t* in, uint8_t* out);
			void decrypt_block(const uint8_t* in, uint8_t* out);
			void clear();

		protected:
			uint32_t rk[40];
			uint32_t s[4][256];
		};
	}

	class twofish128 : public detail::twofish
	{
	public:
		size_t keysize() const { return 128; }
		block_cipher* clone() const { return new twofish128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class twofish192 : public detail::twofish
	{
	public:
		size_t keysize() const { return 192; }
		block_cipher* clone() const { return new twofish192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class twofish256 : public detail::twofish
	{
	public:
		size_t keysize() const { return 256; }
		block_cipher* clone() const { return new twofish256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

}

#endif

