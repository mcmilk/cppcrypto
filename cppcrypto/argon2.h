/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ARGON2_H
#define CPPCRYPTO_ARGON2_H

#include <stdint.h>
#include "pbkdf2.h"

namespace cppcrypto
{
	/*
	Argon2 key derivation function.
	There are two versions of Argon2: argon2i and argon2d.
	Argon2i is the safest against side-channel attacks, while Argon2d provides the highest resistance against GPU cracking attacks.

	Input:
	password Passphrase.
	salt     Salt.
	t        A time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations.
	m        A memory cost, which defines the memory usage, given in kibibytes.
	p        A parallelism degree, which defines the number of parallel threads.
	dklen    Intended output length of the derived key, given in bytes.

	Optional input:
	data     Associated data which will affect the derived key.
	secret   Secret value which will affect the derived key.

	Output:
	dk       Derived key, of length dklen bytes.

	Example:

	    uint8_t dk[32];
	    argon2i("password", 8, (const uint8_t*)"salt", 4, 4, 4096, 1000, dk, sizeof(dk));

	*/
	void argon2d(const char* password, uint32_t pwd_len, const uint8_t* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, uint8_t* dk, uint32_t dklen,
		uint8_t* data = nullptr, uint32_t datalen = 0, uint8_t* secret = nullptr, uint32_t secretlen = 0);
	void argon2i(const char* password, uint32_t pwd_len, const uint8_t* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, uint8_t* dk, uint32_t dklen,
		uint8_t* data = nullptr, uint32_t datalen = 0, uint8_t* secret = nullptr, uint32_t secretlen = 0);
}

#endif

