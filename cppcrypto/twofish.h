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
			~twofish();

			size_t blocksize() const override { return 128; }
			void encrypt_block(const uint8_t* in, uint8_t* out) override;
			void decrypt_block(const uint8_t* in, uint8_t* out) override;
			void clear() override;

		protected:
			uint32_t rk[40];
			uint32_t s[4][256];
		};
	}

	class twofish128 : public detail::twofish
	{
	public:
		size_t keysize() const override { return 128; }
		twofish128* clone() const override { return new twofish128; }

		bool init(const uint8_t* key, block_cipher::direction direction) override;
	};

	class twofish192 : public detail::twofish
	{
	public:
		size_t keysize() const override { return 192; }
		twofish192* clone() const override { return new twofish192; }

		bool init(const uint8_t* key, block_cipher::direction direction) override;
	};

	class twofish256 : public detail::twofish
	{
	public:
		size_t keysize() const override { return 256; }
		twofish256* clone() const override { return new twofish256; }

		bool init(const uint8_t* key, block_cipher::direction direction) override;
	};

}

#endif

