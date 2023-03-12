/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SERPENT_IMPL_H
#define CPPCRYPTO_SERPENT_IMPL_H

#include <stdint.h>
#include <emmintrin.h>
#include "block_cipher.h"

namespace cppcrypto
{
	namespace detail
	{
		class serpent_impl
		{
		public:
			virtual ~serpent_impl() {}
			virtual void encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* W, cppcrypto::block_cipher& cipher) = 0;
			virtual void decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* W, cppcrypto::block_cipher& cipher) = 0;
			virtual void init(uint32_t* w) = 0;

		};

		class serpent_impl_avx2 : public serpent_impl
		{
		public:
			void encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* W, cppcrypto::block_cipher& cipher) override;
			void decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* W, cppcrypto::block_cipher& cipher) override;

			void init(uint32_t* w) override;
		};

	}
}
#endif
