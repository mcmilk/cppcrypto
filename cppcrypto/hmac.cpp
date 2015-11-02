
#include "hmac.h"
#include <memory.h>

namespace cppcrypto
{
	hmac::hmac(const crypto_hash& hash, const std::string& key)
		: ipad_(0), opad_(0), hash_(hash.clone())
	{
		construct(reinterpret_cast<const uint8_t*>(&key[0]), key.length());
	}

	hmac::hmac(const crypto_hash& hash, const uint8_t* key, size_t keylen)
		: ipad_(0), opad_(0), hash_(hash.clone())
	{
		construct(key, keylen);
	}

	void hmac::construct(const uint8_t* key, size_t keylen)
	{
		int nb = blockbitlen() / 8;
		ipad_ = new uint8_t[nb];
		opad_ = new uint8_t[nb];
		memset(ipad_, 0, nb);
		memset(opad_, 0, nb);

		if (keylen > static_cast<size_t>(nb))
		{
			hash_->hash_string(key, keylen, ipad_);
			memcpy(opad_, ipad_, hashbitlen()/8);
		}
		else
		{
			memcpy(ipad_, key, keylen);
			memcpy(opad_, key, keylen);
		}

		for (int i = 0; i < nb; i++)
		{
			opad_[i] ^= 0x5c;
			ipad_[i] ^= 0x36;
		}
	}

	hmac::~hmac()
	{
		delete[] ipad_;
		delete[] opad_;
	}

	void hmac::update(const uint8_t* data, size_t len)
	{
		hash_->update(data, len);
	}

	void hmac::init()
	{
		hash_->init();
		hash_->update(ipad_, blockbitlen()/8); 
	};

	void hmac::final(uint8_t* hash)
	{
		uint8_t* temp = new uint8_t[hashbitlen()/8];
		hash_->final(temp);
		hash_->init();
		hash_->update(opad_, blockbitlen()/8);
		hash_->update(temp, hashbitlen()/8);
		delete[] temp;
		hash_->final(hash);
	}

	crypto_hash* hmac::clone() const
	{
		hmac* clone = new hmac(*hash_, ipad_, 0);
		int nb = blockbitlen() / 8;
		memcpy(clone->ipad_, ipad_, nb);
		memcpy(clone->opad_, opad_, nb);
		return clone;
	}

}