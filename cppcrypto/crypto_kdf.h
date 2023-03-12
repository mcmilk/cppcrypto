/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KDF_H
#define CPPCRYPTO_KDF_H

#include <stdlib.h>

namespace cppcrypto
{

class crypto_kdf
{
public:
	virtual ~crypto_kdf() = default;

	virtual void derive_key(const unsigned char* ikm, size_t ikm_len, const unsigned char* random_data, size_t random_data_len, unsigned char* dk, size_t dklen) const = 0;

	void gen_random_data_and_derive_key(const unsigned char* ikm, size_t ikm_len, size_t random_data_len, unsigned char* random_data, unsigned char* dk, size_t dklen) const;

	virtual crypto_kdf* clone() const = 0;

	virtual void clear() = 0;
};

}

#endif
