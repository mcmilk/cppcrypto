/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "streaming_aead.h"
#include "random_bytes.h"
#include "aead_etm.h"
#include <stdexcept>

namespace cppcrypto
{
	streaming_aead::streaming_aead(const aead& aead) 
		: aead_(aead.clone()) 
	{
	}

	streaming_aead::~streaming_aead()
	{
	}

	void streaming_aead::init_encryption(const unsigned char* ikm, size_t ikmlen, unsigned char* header, size_t header_len, const crypto_kdf& kdf)
	{
		if (header_len != header_bytes())
			throw std::runtime_error("invalid header length");

		header[0] = static_cast<unsigned char>(header_bytes());
		std::basic_string<unsigned char> key(aead_->key_bytes(), 0);
		kdf.gen_random_data_and_derive_key(ikm, ikmlen, salt_bytes(), header + 1, &key[0], key.length());

		size_t iv_size = std::max(nonce_prefix_bytes() + 5, aead_->iv_bytes());
		iv_.assign(iv_size, 0);

		gen_random_bytes(&iv_[0], nonce_prefix_bytes());
		memcpy(header + 1 + salt_bytes(), iv_.data(), 7);
		aead_->set_key(key.data(), key.length());
	}

	void streaming_aead::init_decryption(const unsigned char* ikm, size_t ikmlen, const unsigned char* header, size_t header_len, const crypto_kdf& kdf)
	{
		if (header_len != header_bytes())
			throw std::runtime_error("invalid header length");

		if (header[0] != static_cast<unsigned char>(header_bytes()))
			throw std::runtime_error("invalid header");

		std::basic_string<unsigned char> key(aead_->key_bytes(), 0);
		kdf.derive_key(ikm, ikmlen, header + 1, salt_bytes(), &key[0], key.length());
		size_t iv_size = std::max(nonce_prefix_bytes() + 5, aead_->iv_bytes());
		iv_.assign(iv_size, 0);

		memcpy(&iv_[0], header + 1 + salt_bytes(), nonce_prefix_bytes());
		aead_->set_key(key.data(), key.length());
	}

	void streaming_aead::encrypt_segment(segment_type type, const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len)
	{
		uint32_t* ctr = reinterpret_cast<uint32_t*>(&iv_[nonce_prefix_bytes()]);
		++*ctr;
		iv_[nonce_prefix_bytes() + 4] = type == segment_type::final ? 1 : 0;
		aead_->encrypt_with_explicit_iv(plaintext, plaintext_len, associated_data, associated_data_len, iv_.data(), iv_.length(), result, result_buffer_len);
	}

	bool streaming_aead::decrypt_segment(segment_type type, const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len)
	{
		uint32_t* ctr = reinterpret_cast<uint32_t*>(&iv_[nonce_prefix_bytes()]);
		++*ctr;
		iv_[nonce_prefix_bytes() + 4] = type == segment_type::final ? 1 : 0;
		return aead_->decrypt_with_explicit_iv(ciphertext, ciphertext_len, associated_data, associated_data_len, iv_.data(), iv_.length(), result, result_buffer_len);
	}

	size_t streaming_aead::tag_bytes() const
	{
		return aead_->tag_bytes(); 
	}

	size_t streaming_aead::header_bytes() const 
	{ 
		return 1 + nonce_prefix_bytes() + salt_bytes(); 
	}

	size_t streaming_aead::nonce_prefix_bytes() const
	{
		return aead_->iv_prefix_bytes_for_streaming_aead();
	}

	size_t streaming_aead::salt_bytes() const
	{
		aead_etm* etm = dynamic_cast<aead_etm*>(aead_.get());
		if (etm)
			return etm->cipher_key_bytes();

		return aead_->key_bytes();
	}

}

