/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_HKDF_H
#define CPPCRYPTO_HKDF_H

#include "crypto_kdf.h"
#include "hmac.h"

namespace cppcrypto
{

/*
HKDF is a HMAC based key derivation function (KDF).
It can be used to extract randomness from the source key material and/or expand the key into a larger output, for example, to create multiple keys from a single key.

Note that HKDF is not suitable for generating keys from passwords. For that purpose, use password-based KDFs such as argon2, lyra2, etc.
*/
class hkdf : public crypto_kdf
{
public:
	hkdf(const crypto_hash& hash);
	~hkdf();

	/*
	   Extract pseudorandom key from source key material and optional extractor salt.

	   Input:
	   skm      Source key material (must not be a password).
	   xts      Extractor salt (optional).
	   prk_len  Length of the extracted key in bytes. Must be equal to hash size of the hash function.

	   Output:
	   prk      Extracted pseudo-random key.
	*/
	void extract(const unsigned char* xts, size_t xts_len, const unsigned char* skm, size_t skm_len, unsigned char* prk, size_t prk_len) const;

	/*
           Expand pseudorandom key into desired size.

	   Input:
	   prk      Pseudorandom key to be expanded.
	   ctxinfo  Context information.
	   okm_len  Length of the output keying material in bytes.

	   Output:
	   okm      Output keying material (expanded key).
	*/
	void expand(const unsigned char* prk, size_t prk_len, const unsigned char* ctxinfo, size_t ctxinfo_len, unsigned char* okm, size_t okm_len) const;

	/*
	   Extract pseudorandom key from source key material and optional extractor salt, then expand pseudorandom key into desired size.

	   Input:
	   skm      Source key material (must not be a password).
	   xts      Extractor salt (optional).
	   ctxinfo  Context information.
	   okm_len  Length of the output keying material in bytes.

	   Output:
	   okm      Output keying material (expanded key).
	*/
	void extract_and_expand(const unsigned char* xts, size_t xts_len, const unsigned char* ctxinfo, size_t ctxinfo_len, const unsigned char* skm, size_t skm_len, unsigned char* okm, size_t okm_len) const;

	/*
	   Derive key from the input key material and random data. Implements the crypto_kdf interface.
           This method does not allow to specify extractor salt, if it is needed, use extract_and_expand instead.

	   Input:
	   ikm         Input key material. Must not be a password.
	   random_data Random data. Will be used in the Expand stage as context information.
	   okm_len     Length of the derived key in in bytes.

	   Output:
	   dk          Derived key.
	*/
	virtual void derive_key(const unsigned char* ikm, size_t ikm_len, const unsigned char* random_data, size_t random_data_len, unsigned char* dk, size_t dklen) const override;

	/*
	   Initial counter value for the Expand stage.
           By default the initial counter value is 1, as specified in RFC 5869.
           If compatibility with the original paper is needed, it can be changed to 0.
	*/
	void set_initial_counter_value(uint8_t counter);

	hkdf* clone() const override;

	void clear() override;
private:
	std::unique_ptr<crypto_hash> hash_;
	uint8_t counter_ = 1;
};

}

#endif
