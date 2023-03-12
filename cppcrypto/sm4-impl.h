/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SM4_IMPL_H
#define CPPCRYPTO_SM4_IMPL_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
	namespace detail
	{
		class sm4_impl
		{
		public:
			virtual ~sm4_impl() {}
			virtual bool init(const unsigned char* key, block_cipher::direction direction) = 0;
			virtual void encrypt_block(const unsigned char* in, unsigned char* out) = 0;
			virtual void decrypt_block(const unsigned char* in, unsigned char* out) = 0;
			virtual void encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) = 0;
			virtual void decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) = 0;
		};

		class sm4_impl_aesni : public sm4_impl
		{
		public:
			virtual bool init(const unsigned char* key, block_cipher::direction direction) override;
			virtual void encrypt_block(const unsigned char* in, unsigned char* out) override;
			virtual void decrypt_block(const unsigned char* in, unsigned char* out) override;
			virtual void encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) override;
			virtual void decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n) override;
		private:
			alignas(16) uint32_t rk[32];
		};
	}
}



#endif
