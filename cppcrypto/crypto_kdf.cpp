/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "crypto_kdf.h"
#include "random_bytes.h"

namespace cppcrypto
{
	void crypto_kdf::gen_random_data_and_derive_key(const unsigned char* ikm, size_t ikm_len, size_t random_data_len, unsigned char* random_data, unsigned char* dk, size_t dklen) const
	{
		gen_random_bytes(random_data, random_data_len);
		return derive_key(ikm, ikm_len, random_data, random_data_len, dk, dklen);
	}

}
