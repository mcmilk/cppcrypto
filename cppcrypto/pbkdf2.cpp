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
	pbkdf2::pbkdf2(const crypto_hash& hash, size_t iterations)
		: hash_(hash.clone()), iterations_(iterations)
	{
	}

	pbkdf2::~pbkdf2()
	{
		clear();
	}

	pbkdf2* pbkdf2::clone() const
	{
		return new pbkdf2(*hash_, iterations_);
	}

	void pbkdf2::clear()
	{
		hash_->clear();
	}

	void pbkdf2::set_iterations(size_t iterations)
	{
		iterations_ = iterations;
	}

	void pbkdf2::derive_key(const unsigned char* password, size_t pwd_len, const unsigned char* salt, size_t salt_len, unsigned char* dk, size_t dklen) const
	{
		hmac hmac(*hash_);
		size_t hlen = hmac.hashsize() / 8;
		unsigned char* res = dk;
		unsigned char* temp1 = new unsigned char[hlen * 2];
		size_t remaining = dklen;

		for (uint32_t i = 0; res < dk + dklen; i++)
		{
			hmac.init(password, pwd_len);
			hmac.update(salt, salt_len);
			uint32_t ir = swap_uint32(i + 1);
			hmac.update((const unsigned char*)&ir, sizeof(ir));
			hmac.final(temp1);
			size_t sz = std::min(hlen, remaining);
			memcpy(res, temp1, sz);
			for (size_t c = 1; c < iterations_; c++)
			{
				hmac.mac_string(password, pwd_len, temp1, hlen, temp1 + hlen);
				for (size_t i = 0; i < sz; i++)
					res[i] ^= temp1[hlen + i];
				memcpy(temp1, temp1 + hlen, hlen);
			}
			res += sz;
			remaining -= sz;
	}

		delete[] temp1;
	}

}
