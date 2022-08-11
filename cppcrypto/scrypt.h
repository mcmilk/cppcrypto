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

	Input:
	hmac    HMAC to use (e.g. HMAC-SHA-256). The password shall be passed to the constructor of hmac object.
	salt    Salt.
	N       CPU/Memory cost parameter, must be larger than 1, a power of 2 and less than 2^(16*r).
	r       Block size factor parameter.
	p       Parallelization parameter, a positive integer less than (2^30)/r.
	dklen   Intended output length of the derived key; a positive integer less than or equal to (2^32 - 1) * 32.

	Output:
	dk      Derived key, of length dklen bytes.

	Example:

	    unsigned char dk[32];
	    scrypt(hmac(sha256(), "password"), (const unsigned char*)"salt", 4, 16384, 8, 16, dk, sizeof(dk));

	*/
	void scrypt(hmac& hmac, const unsigned char* salt, size_t salt_len, size_t N, size_t r, size_t p, unsigned char* dk, size_t dklen);
}


#endif

