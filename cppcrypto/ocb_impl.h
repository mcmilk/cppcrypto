/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_OCB_IMPL_H
#define CPPCRYPTO_AEAD_OCB_IMPL_H

#include "block_cipher.h"
#include <memory>

namespace cppcrypto
{
namespace detail
{
	class ocb_impl
	{
	public:
		virtual ~ocb_impl() {}
		virtual void set_key(const unsigned char* key, size_t keylen) = 0;

		virtual void encrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out, size_t tag_bytes) = 0;
		virtual bool decrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out, size_t tag_bytes) = 0;

		virtual size_t max_iv_bytes() const = 0;
		virtual size_t keysize_in_bytes() const = 0;

		virtual const std::unique_ptr<block_cipher>& get_cipher() const = 0;
	};

}

}

#endif
