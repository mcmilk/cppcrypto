/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_H
#define CPPCRYPTO_AEAD_H

#include <string>

namespace cppcrypto
{
	class aead
	{
	public:
		virtual ~aead();

		// key setup

		virtual void set_key(const unsigned char* key, size_t keylen) = 0;

		virtual void set_tagsize_in_bits(size_t tagsize_in_bits) = 0;

		// encrypt

		void encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len);

		void encrypt_with_explicit_iv(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result, size_t result_buffer_len);

		// decrypt 

		bool decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len);

		bool decrypt_with_explicit_iv(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result, size_t result_buffer_len);

		// informational getters

		virtual size_t key_bytes() const = 0;

		virtual size_t iv_bytes() const = 0;

		virtual size_t tag_bytes() const = 0;

		virtual aead* clone() const = 0;

	protected:

		virtual void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) = 0;

		virtual bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) = 0;

		virtual size_t iv_prefix_bytes_for_streaming_aead() const { return iv_bytes() - 5; }

		friend class streaming_aead;
	};

}

#endif
