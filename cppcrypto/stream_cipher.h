/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_STREAM_CIPHER_H
#define CPPCRYPTO_STREAM_CIPHER_H

#include <stdint.h>
#include <string>

namespace cppcrypto
{

	class stream_cipher
	{
	public:
		stream_cipher() {}
		virtual ~stream_cipher() {}

		virtual size_t keysize() const = 0;
		virtual size_t ivsize() const = 0;
		virtual stream_cipher* clone() const = 0;
		virtual void clear() = 0;

		virtual void init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen) = 0;
		virtual void encrypt(const unsigned char* in, size_t len, unsigned char* out) = 0;
		virtual void decrypt(const unsigned char* in, size_t len, unsigned char* out) = 0;

	protected:
		virtual size_t max_nonce_bytes_for_aead() const { return ivsize() / 8; }

	private:
		stream_cipher(const stream_cipher&) = delete;
		void operator=(const stream_cipher&) = delete;

		friend class aead_etm;
		friend class aead_ietf_chacha_poly;
	};

}

#endif
