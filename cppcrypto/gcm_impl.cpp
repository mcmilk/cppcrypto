/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "gcm_impl.h"

namespace cppcrypto
{
    namespace detail
    {
        gcm_impl::gcm_impl(const block_cipher& cipher)
            : cipher_(cipher.clone())
        {

        }

        void gcm_impl::set_tagsize_in_bits(size_t tagsize)
        {
            tagsize_in_bits = tagsize;
        }

        size_t gcm_impl::keysize_in_bytes() const
        {
            return cipher_->keysize() / 8;
        }

        size_t gcm_impl::tagsize_in_bytes() const
        {
            return tagsize_in_bits / 8;
        }

	const std::unique_ptr<block_cipher>& gcm_impl::get_cipher() const
	{

		return cipher_;
	}

    }

}
 
