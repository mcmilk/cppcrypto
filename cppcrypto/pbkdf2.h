/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_PBKDF2_H
#define CPPCRYPTO_PBKDF2_H

#include <stdint.h>
#include "hmac.h"
#include "crypto_kdf.h"

namespace cppcrypto
{

	/*
	PBKDF2 key derivation function.
	Input:
	password, salt, number of iterations, hash algorithm, and required derived key length.

	Output:
	dk       Derived key, of length dklen bytes.

	Example:

	    unsigned char dk[32];
	    pbkdf2(sha256(), 16777216).derive_key((const unsigned char*)"password", 8, (const unsigned char*)"salt", 4, dk, sizeof(dk));

	*/
	class pbkdf2 : public crypto_kdf
	{
	public:
		pbkdf2(const crypto_hash& hash, size_t iterations);

		~pbkdf2();

		pbkdf2* clone() const override;

		void clear() override;

		// Change number of iterations.
		void set_iterations(size_t iterations);

		void derive_key(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned char* dk, size_t dklen) const override;

	private:
		std::unique_ptr<crypto_hash> hash_;
		size_t iterations_;

	};
}


#endif

