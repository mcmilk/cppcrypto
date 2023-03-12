/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_SCHWAEMM_H
#define CPPCRYPTO_AEAD_SCHWAEMM_H

#include "aead.h"
#include "schwaemm_impl.h"
#include "alignedarray.h"
#include <memory>

namespace cppcrypto
{
	class schwaemm : public aead
	{
	public:
		enum class variant
		{
			schwaemm256_256,
			schwaemm256_128,
			schwaemm192_192
		};

		schwaemm(variant var);

		~schwaemm();

		void set_key(const unsigned char* key, size_t keylen) override;

		void set_tagsize_in_bits(size_t tagsize_in_bits) override;

		size_t iv_bytes() const override;
		size_t tag_bytes() const override;
		size_t key_bytes() const override;

		virtual schwaemm* clone() const override { return new schwaemm(variant_); }

		void clear();

	private:
		void do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		bool do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result) override;

		aligned_impl_ptr<detail::schwaemm_impl, 32> impl_;
		variant variant_;
		std::basic_string<unsigned char> key_;
	};

}

#endif
