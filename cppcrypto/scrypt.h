/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SCRYPT_H
#define CPPCRYPTO_SCRYPT_H

#include <stdint.h>
#include "pbkdf2.h"

namespace cppcrypto
{
	/*
	scrypt key derivation function.

	Example:

		unsigned char dk[32];
		scrypt(sha256(), 16384, 8, 16).derive_key((const unsigned char*)"password", 8, (const unsigned char*)"salt", 4, dk, sizeof(dk));

	*/
	class scrypt : public crypto_kdf
	{
	public:
		/*
		   Scrypt key derivation function.
		   Parameters:
		   hash    Hash to use for HMAC (e.g. SHA-256).
		   N       CPU/Memory cost parameter, must be larger than 1, a power of 2 and less than 2^(16*r).
		   r       Block size factor parameter.
		   p       Parallelization parameter, a positive integer less than (2^30)/r.
		*/
		scrypt(const crypto_hash& hash, size_t N, size_t r, size_t p);

		// Change CPU/Memory cost parameter, must be larger than 1, a power of 2 and less than 2^(16*r)
		void set_N(size_t N);

		// Change Block size factor parameter.
		void set_r(size_t r);

		// Change Parallelization parameter, a positive integer less than (2^30)/r.
		void set_p(size_t p);

		scrypt* clone() const override;

		void clear() override;

		/*
		   Derive a key from a password.

		   Input:
		   password Passphrase.
		   salt     Salt.
		   dklen    Intended output length of the derived key, given in bytes.

		   Output:
		   dk       Derived key, of length dklen bytes.
		*/
		void derive_key(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned char* dk, size_t dklen) const override;

	private:
		std::unique_ptr<crypto_hash> hash_;
		size_t N_;
		size_t r_;
		size_t p_;
	};
}


#endif

