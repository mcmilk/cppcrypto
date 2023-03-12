/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_GCM_H
#define CPPCRYPTO_AEAD_GCM_H

#include "gcm_impl.h"
#include "aead.h"
#include "crypto_mac.h"
#include "block_cipher.h"
#include "crypto_kdf.h"
#include <memory>

namespace cppcrypto
{
	class aead_gcm : public aead
	{
	public:
		aead_gcm(const block_cipher& cipher);

		~aead_gcm();

		void set_key(const unsigned char* key, size_t keylen) override;

		void set_tagsize_in_bits(size_t tagsize_in_bits) override;

		size_t iv_bytes() const override;
		size_t tag_bytes() const override { return impl_->tagsize_in_bytes(); }
		size_t key_bytes() const override { return impl_->keysize_in_bytes(); }

		virtual aead_gcm* clone() const override { return new aead_gcm(*impl_->get_cipher()); }

	private:
		void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		std::unique_ptr<detail::gcm_impl> impl_;
		bool initialized_ = false;
	};

}

#endif

