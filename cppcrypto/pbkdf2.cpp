/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "pbkdf2.h"
#include "portability.h"
#include <algorithm>
#include <memory.h>

namespace cppcrypto
{
	void pbkdf2(hmac& hmac, const unsigned char* salt, size_t salt_len, int iterations, unsigned char* dk, size_t dklen)
	{
		size_t hlen = hmac.hashsize() / 8;
		unsigned char* res = dk;
		unsigned char* temp1 = new unsigned char[hlen*2];
		size_t remaining = dklen;

		for (uint32_t i = 0; res < dk + remaining; i++)
		{
			hmac.init();
			hmac.update(salt, salt_len);
			uint32_t ir = swap_uint32(i + 1);
			hmac.update((const unsigned char*)&ir, sizeof(ir));
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
