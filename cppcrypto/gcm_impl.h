/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_GCM_IMPL_H
#define CPPCRYPTO_AEAD_GCM_IMPL_H

#include "block_cipher.h"
#include <memory>

namespace cppcrypto
{
	namespace detail
	{
		class gcm_impl
		{
		public:
			gcm_impl(const block_cipher& cipher);
			virtual ~gcm_impl() {}
			virtual void set_key(const unsigned char* key, size_t keylen) = 0;
			virtual void set_tagsize_in_bits(size_t tagsize);

			virtual void encrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out) = 0;
			virtual bool decrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out) = 0;

			size_t keysize_in_bytes() const;
			size_t tagsize_in_bytes() const;

			const std::unique_ptr<block_cipher>& get_cipher() const;
		protected:
			std::unique_ptr<block_cipher> cipher_;
			size_t tagsize_in_bits = 128;
		};

		class gcm_impl_clmul : public gcm_impl
		{
		public:
			gcm_impl_clmul(const block_cipher& cipher);
			virtual ~gcm_impl_clmul();
			virtual void set_key(const unsigned char* key, size_t keylen) override;

			virtual void encrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out) override;
			virtual bool decrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out) override;
		};

	}
}

#endif
