/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_ETM_H
#define CPPCRYPTO_AEAD_ETM_H

#include "aead.h"
#include "crypto_mac.h"
#include "stream_cipher.h"
#include "random_bytes.h"
#include "crypto_kdf.h"
#include <memory>

namespace cppcrypto
{
	class aead_etm : public aead
	{
	public:
		aead_etm(const stream_cipher& cipher, const crypto_mac& mac);

		~aead_etm();

		// Set combined key. The size must be equal to the sum of cipher key size and MAC key size.
		void set_key(const unsigned char* key, size_t keylen) override;

		void set_tagsize_in_bits(size_t tagsize_in_bits) override;

		inline size_t cipher_key_bytes() const { return cipher_->keysize() / 8; }
		inline size_t mac_key_bytes() const { return mac_->keysize() / 8; }
		size_t iv_bytes() const override { return cipher_->ivsize() / 8; }
		size_t tag_bytes() const override { return tagsize_in_bits / 8; }
		size_t key_bytes() const override { return cipher_key_bytes() + mac_key_bytes(); }

		virtual aead_etm* clone() const override { return new aead_etm(*cipher_, *mac_); }

	private:
		void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;
		bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		size_t iv_prefix_bytes_for_streaming_aead() const override { return cipher_->max_nonce_bytes_for_aead() - 5; }

		std::unique_ptr<stream_cipher> cipher_;
		std::unique_ptr<crypto_mac> mac_;
		std::string key_;
		size_t tagsize_in_bits;
	};

}

#endif
