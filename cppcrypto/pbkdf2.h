/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_PBKDF2_H
#define CPPCRYPTO_PBKDF2_H

#include <stdint.h>
#include "hmac.h"

namespace cppcrypto
{
	void pbkdf2(hmac& hmac, const uint8_t* salt, size_t salt_len, int iterations, uint8_t* dk, size_t dklen);
}


#endif