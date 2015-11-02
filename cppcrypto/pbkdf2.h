/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_PBKDF2_H
#define CPPCRYPTO_PBKDF2_H

#include <stdint.h>
#include "hmac.h"

namespace cppcrypto
{
	void PBKDF2(hmac& hmac, const uint8_t* salt, size_t salt_len, int iterations, uint8_t* dk, size_t dklen);
}


#endif