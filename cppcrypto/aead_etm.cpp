/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aead_etm.h"
#include "functions.h"
#include "portability.h"
#include <stdexcept>
#include <string.h>

namespace cppcrypto
{
	aead_etm::aead_etm(const stream_cipher& cipher, const crypto_mac& mac)
		: cipher_(cipher.clone()), mac_(mac.clone()), tagsize_in_bits(mac.hashsize())
	{
	}

	aead_etm::~aead_etm()
	{
		if (!key_.empty())
			zero_memory(&key_[0], key_.length());
	}

	void aead_etm::set_key(const unsigned char* key, size_t keylen)
	{
		if (!key_.empty())
			zero_memory(&key_[0], key_.length());
		if (keylen < key_bytes())
			throw std::runtime_error("invalid key size");
		key_.assign(reinterpret_cast<const char*>(key), keylen);
	}

	void aead_etm::do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!key_.length())
			throw std::runtime_error("key not set");

		if (iv_len != iv_bytes())
			throw std::runtime_error("incorrect iv size");

		mac_->init(reinterpret_cast<const unsigned char*>(key_.data() + cipher_key_bytes()), key_.length() - cipher_key_bytes());
		mac_->set_tagsize_in_bits(tagsize_in_bits);
		if (plaintext_len)
		{
			cipher_->init(reinterpret_cast<const unsigned char*>(key_.data()), cipher_key_bytes(), iv, iv_len);
			cipher_->encrypt(plaintext, plaintext_len, result);
		}
		mac_->update(associated_data, associated_data_len);
		mac_->update(iv, iv_len);
		mac_->update(result, plaintext_len);
		uint64_t adlen = swap_uint64(static_cast<uint64_t>(associated_data_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&adlen), sizeof(adlen));
		uint64_t ivlen = swap_uint64(static_cast<uint64_t>(iv_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&ivlen), sizeof(ivlen));
		uint64_t ptlen = swap_uint64(static_cast<uint64_t>(plaintext_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&ptlen), sizeof(ptlen));
		mac_->final(result + plaintext_len);
	}

	bool aead_etm::do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!key_.length())
			throw std::runtime_error("key not set");

		if (iv_len != iv_bytes())
			throw std::runtime_error("incorrect iv size");

		std::string tag;
		tag.resize(tag_bytes());
		if (ciphertext_len < tag_bytes())
			return false;

		size_t plaintext_len = ciphertext_len - tag_bytes();

		mac_->init(reinterpret_cast<const unsigned char*>(key_.data() + cipher_key_bytes()), key_.length() - cipher_key_bytes());
		mac_->set_tagsize_in_bits(tagsize_in_bits);
		mac_->update(associated_data, associated_data_len);
		mac_->update(iv, iv_len);
		mac_->update(ciphertext, plaintext_len);
		uint64_t adlen = swap_uint64(static_cast<uint64_t>(associated_data_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&adlen), sizeof(adlen));
		uint64_t ivlen = swap_uint64(static_cast<uint64_t>(iv_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&ivlen), sizeof(ivlen));
		uint64_t ptlen = swap_uint64(static_cast<uint64_t>(plaintext_len * 8));
		mac_->update(reinterpret_cast<unsigned char*>(&ptlen), sizeof(ptlen));
		mac_->final(reinterpret_cast<unsigned char*>(&tag[0]));

		if (!tag_matches(reinterpret_cast<const unsigned char*>(tag.data()), ciphertext + plaintext_len, tag_bytes()))
			return false;

		if (plaintext_len)
		{
			cipher_->init(reinterpret_cast<const unsigned char*>(key_.data()), cipher_key_bytes(), iv, iv_bytes());
			cipher_->decrypt(ciphertext, plaintext_len, result);
		}
		return true;

	}

	void aead_etm::set_tagsize_in_bits(size_t tagsize)
	{
		if (!tagsize || tagsize > mac_->hashsize() || tagsize % 8 != 0)
			throw std::runtime_error("invalid tag size");

		tagsize_in_bits = tagsize;
	}
}


