/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CTR_SSE41_H
#define CPPCRYPTO_CTR_SSE41_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{
namespace detail
{
	void increment_and_encrypt8_block128(unsigned char* ctr, size_t nb, uint32_t** ctrs, uint32_t& counter, unsigned char* block, block_cipher* cipher);
}
}

#endif
