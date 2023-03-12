/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aead.h"
#include "random_bytes.h"
#include <stdexcept>

namespace cppcrypto
{
	aead::~aead()
	{
	}

	void aead::encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len)
	{
		if (result_buffer_len != iv_bytes() + plaintext_len + tag_bytes())
			throw std::runtime_error("wrong buffer size");

		gen_random_bytes(result, iv_bytes());

		do_encrypt(plaintext, plaintext_len, associated_data, associated_data_len,
			result, iv_bytes(), result + iv_bytes());
	}

	bool aead::decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len)
	{
		if (result_buffer_len != ciphertext_len - iv_bytes() - tag_bytes())
			throw std::runtime_error("wrong buffer size");

		if (ciphertext_len < iv_bytes())
			return false;
		
		return do_decrypt(ciphertext + iv_bytes(), ciphertext_len - iv_bytes(), associated_data, associated_data_len, ciphertext, iv_bytes(), result);
	}

	void aead::encrypt_with_explicit_iv(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result, size_t result_buffer_len)
	{
		if (result_buffer_len != plaintext_len + tag_bytes())
			throw std::runtime_error("wrong buffer size");

		do_encrypt(plaintext, plaintext_len, associated_data, associated_data_len, iv, iv_len, result);
	}

	bool aead::decrypt_with_explicit_iv(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result, size_t result_buffer_len)
	{
		if (result_buffer_len != ciphertext_len - tag_bytes())
			throw std::runtime_error("wrong buffer size");

		return do_decrypt(ciphertext, ciphertext_len, associated_data, associated_data_len, iv, iv_len, result);
	}
}

