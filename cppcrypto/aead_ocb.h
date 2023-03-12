/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_OCB_H
#define CPPCRYPTO_AEAD_OCB_H

#include "aead.h"
#include "crypto_mac.h"
#include "block_cipher.h"
#include "crypto_kdf.h"
#include "ocb_impl.h"
#include "alignedarray.h"
#include <memory>

namespace cppcrypto
{
	class aead_ocb : public aead
	{
	public:
		// Constructor.
		aead_ocb(const block_cipher& cipher);

		~aead_ocb();

		void set_key(const unsigned char* key, size_t keylen) override;

		size_t iv_bytes() const override;
		size_t tag_bytes() const override { return tagsize_in_bits / 8; }
		size_t key_bytes() const override { return impl_->keysize_in_bytes(); }

		virtual aead_ocb* clone() const override;

		// Default tag size is equal to the minimum of 256 or block size of the cipher.
		void set_tagsize_in_bits(size_t tagsize_in_bits) override;

	private:
		void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		aligned_impl_ptr<detail::ocb_impl, 16> impl_;
		size_t tagsize_in_bits;
		bool initialized_ = false;
	};

}

#endif
