/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "schwaemm.h"
#include "portability.h"
#include "random_bytes.h"
#include <stdexcept>
#include <string.h>
//#define NO_OPTIMIZED_VERSIONS
#include "cpuinfo.h"

#ifndef NO_OPTIMIZED_VERSIONS
#include "schwaemm_impl_avx2.h"
#endif

namespace cppcrypto
{
	schwaemm::schwaemm(schwaemm::variant var)
		: variant_(var)
	{
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info().avx2())
		{
			switch (var)
			{
			case variant::schwaemm256_256:
				impl_.create<detail::schwaemm256_256_avx2>();
				break;
			case variant::schwaemm256_128:
				impl_.create<detail::schwaemm256_128_avx2>();
				break;
			case variant::schwaemm192_192:
				impl_.create<detail::schwaemm192_192_avx2>();
				break;
			}
		}
	    else
#endif
		{
			switch(var)
			{
				case variant::schwaemm256_256:
					impl_.create<detail::schwaemm256_256>();
					break;
				case variant::schwaemm256_128:
					impl_.create<detail::schwaemm256_128>();
					break;
				case variant::schwaemm192_192:
					impl_.create<detail::schwaemm192_192>();
					break;
			}
		}
	}

	schwaemm::~schwaemm()
	{
		clear();
	}

	void schwaemm::clear()
	{
		if (!key_.empty())
			zero_memory(&key_[0], key_.size());
	}

	void schwaemm::set_key(const unsigned char* key, size_t keylen)
	{
		if (keylen != impl_->keysize_in_bytes())
			throw std::runtime_error("invalid schwaemm key size");

		clear();
		key_.assign(key, keylen);
	}

	void schwaemm::set_tagsize_in_bits(size_t tagsize)
	{
		if (!tagsize || tagsize > impl_->tagsize_in_bytes_default() * 8 || tagsize % 8 != 0)
			throw std::runtime_error("invalid schwaemm tag size");

		impl_->set_tagsize_in_bits(tagsize);
	}

	size_t schwaemm::iv_bytes() const
	{
		return impl_->ivsize_in_bytes();
	}

	size_t schwaemm::tag_bytes() const
	{
		return impl_->tagsize_in_bytes();
	}

	size_t schwaemm::key_bytes() const
	{
		return impl_->keysize_in_bytes();
	}

	void schwaemm::do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!key_.length())
			throw std::runtime_error("schwaemm key not set");

		if (iv_len != impl_->ivsize_in_bytes())
			throw std::runtime_error("incorrect schwaemm iv size");

		impl_->encrypt(key_.data(), plaintext, plaintext_len, associated_data, associated_data_len, iv, result);
	}

	bool schwaemm::do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!key_.length())
			throw std::runtime_error("schwaemm key not set");

		if (iv_len != impl_->ivsize_in_bytes())
			throw std::runtime_error("incorrect schwaemm iv size");

		if (ciphertext_len < tag_bytes())
			return false;

		return impl_->decrypt(key_.data(), ciphertext, ciphertext_len, associated_data, associated_data_len, iv, result);
	}

}

