/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "pbkdf2.h"
#include <algorithm>
#include <memory.h>

#ifndef _MSC_VER
#define _byteswap_ulong __builtin_bswap32
#endif

namespace cppcrypto
{
	void PBKDF2(hmac& hmac, const uint8_t* salt, size_t salt_len, int iterations, uint8_t* dk, size_t dklen)
	{
		size_t hlen = hmac.hashbitlen() / 8;
		uint8_t* res = dk;
		uint8_t* temp1 = new uint8_t[hlen*2];
		size_t remaining = dklen;

		for (uint32_t i = 0; res < dk + remaining; i++)
		{
			hmac.init();
			hmac.update(salt, salt_len);
			uint32_t ir = _byteswap_ulong(i+1);
			hmac.update((const uint8_t*)&ir, sizeof(ir));
			hmac.final(temp1);
			size_t sz = std::min(hlen, remaining);
			memcpy(res, temp1, sz);
			for (int c = 1; c < iterations; c++)
			{
				hmac.hash_string(temp1, hlen, temp1 + hlen);
				for (size_t i = 0; i < sz; i++)
					res[i] ^= temp1[hlen + i];
				memcpy(temp1, temp1 + hlen, hlen);
			}
			res += sz;
		}

		delete[] temp1;

	}

}