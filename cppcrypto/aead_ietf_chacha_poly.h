/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_IETF_CHACHA_POLY_H
#define CPPCRYPTO_AEAD_IETF_CHACHA_POLY_H

#include "aead.h"
#include "chacha.h"
#include <memory>

namespace cppcrypto
{
	class aead_ietf_chacha_poly : public aead
	{
	public:
		aead_ietf_chacha_poly(const stream_cipher& cipher = chacha20_256());

		~aead_ietf_chacha_poly();

		void set_key(const unsigned char* key, size_t keylen) override;

		size_t iv_bytes() const override { return cipher_->max_nonce_bytes_for_aead(); }
		size_t tag_bytes() const override { return tagsize_in_bits / 8; }
		size_t key_bytes() const override { return cipher_->keysize() / 8; }

		virtual aead_ietf_chacha_poly* clone() const override { return new aead_ietf_chacha_poly(*cipher_); }

		void set_tagsize_in_bits(size_t tagsize_in_bits) override;
	private:
		void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;
		bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		std::basic_string<unsigned char> key_;
		std::unique_ptr<stream_cipher> cipher_;
		size_t tagsize_in_bits = 128;
	};

}

#endif
