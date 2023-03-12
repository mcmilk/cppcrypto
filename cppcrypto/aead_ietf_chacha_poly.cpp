/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aead_ietf_chacha_poly.h"
#include "functions.h"
#include "portability.h"
#include "poly1305.h"
#include <stdexcept>
#include <string.h>
//#define NO_OPTIMIZED_VERSIONS
#include "cpuinfo.h"

namespace cppcrypto
{

	aead_ietf_chacha_poly::aead_ietf_chacha_poly(const stream_cipher& cipher)
		: cipher_(cipher.clone())
	{
	}

	aead_ietf_chacha_poly::~aead_ietf_chacha_poly()
	{
		zero_memory(&key_[0], key_.length());
	}

	void aead_ietf_chacha_poly::set_key(const unsigned char* key, size_t keylen)
	{
		if (keylen != key_bytes())
			throw std::runtime_error("ietf_chacha_poly keysize must be 32 bytes");

		key_.assign(key, keylen);
}

	void aead_ietf_chacha_poly::do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (key_.empty())
			throw std::runtime_error("key not set");

		if (iv_len != iv_bytes())
			throw std::runtime_error("incorrect iv size");

		std::vector<unsigned char> buf(std::max(static_cast<size_t>(64), cipher_->keysize() / 8));
		memset(&buf[0], 0, buf.size());
		cipher_->init(key_.data(), key_.size(), iv, iv_len);
		cipher_->encrypt(buf.data(), buf.size(), &buf[0]);

		poly1305 poly;
		poly.init(buf.data(), 32);
		memset(buf.data(), 0, buf.size());
		cipher_->encrypt(plaintext, plaintext_len, result);
		poly.update(associated_data, associated_data_len);
		size_t remainder = associated_data_len % 16;
		if (remainder)
			poly.update(buf.data(), 16 - remainder);
		poly.update(result, plaintext_len);
		remainder = plaintext_len % 16;
		if (remainder)
			poly.update(buf.data(), 16 - remainder);
		uint64_t adlen = static_cast<uint64_t>(associated_data_len);
		poly.update(reinterpret_cast<unsigned char*>(&adlen), sizeof(adlen));
		uint64_t ptlen = static_cast<uint64_t>(plaintext_len);
		poly.update(reinterpret_cast<unsigned char*>(&ptlen), sizeof(ptlen));
		result += plaintext_len;

		if (tag_bytes() == 16)
			poly.final(result);
		else
		{
			buf.resize(16);
			poly.final(&buf[0]);
			memcpy(result, buf.data(), tag_bytes());
		}

	}

	bool aead_ietf_chacha_poly::do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (key_.empty())
			throw std::runtime_error("key not set");

		if (iv_len != iv_bytes())
			throw std::runtime_error("incorrect iv size");

		if (ciphertext_len < tag_bytes())
			return false;

		size_t plaintext_len = ciphertext_len - tag_bytes();
		std::vector<unsigned char> buf(std::max(static_cast<size_t>(64), cipher_->keysize() / 8));
		memset(&buf[0], 0, buf.size());
		cipher_->init(key_.data(), key_.size(), iv, iv_len);
		cipher_->encrypt(buf.data(), buf.size(), &buf[0]);

		poly1305 poly;
		poly.init(buf.data(), 32);
		memset(&buf[0], 0, buf.size());

		poly.update(associated_data, associated_data_len);
		size_t remainder = associated_data_len % 16;
		if (remainder)
			poly.update(buf.data(), 16 - remainder);
		poly.update(ciphertext, plaintext_len);
		remainder = plaintext_len % 16;
		if (remainder)
			poly.update(buf.data(), 16 - remainder);
		uint64_t adlen = static_cast<uint64_t>(associated_data_len);
		poly.update(reinterpret_cast<unsigned char*>(&adlen), sizeof(adlen));
		uint64_t ptlen = static_cast<uint64_t>(plaintext_len);
		poly.update(reinterpret_cast<unsigned char*>(&ptlen), sizeof(ptlen));
		buf.resize(16);
		poly.final(&buf[0]);

		if (!tag_matches(ciphertext + plaintext_len, buf.data(), tag_bytes()))
			return false;

		cipher_->decrypt(ciphertext, plaintext_len, result);
		return true;
	}

	void aead_ietf_chacha_poly::set_tagsize_in_bits(size_t tagsize)
	{
		if (!tagsize || tagsize > 128 || tagsize % 8 != 0)
			throw std::runtime_error("invalid tag size");

		tagsize_in_bits = tagsize;
	}
}

