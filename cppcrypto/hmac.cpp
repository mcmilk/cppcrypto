/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "hmac.h"
#include <memory.h>
#include "portability.h"

namespace cppcrypto
{
	hmac::hmac(const crypto_hash& hash, const std::string& key)
		: ipad_(0), opad_(0), hash_(hash.clone())
	{
		construct(reinterpret_cast<const unsigned char*>(&key[0]), key.length());
	}

	hmac::hmac(const crypto_hash& hash, const unsigned char* key, size_t keylen)
		: ipad_(0), opad_(0), hash_(hash.clone())
	{
		construct(key, keylen);
	}

	void hmac::construct(const unsigned char* key, size_t keylen)
	{
		size_t nb = blocksize() / 8;
		ipad_ = new unsigned char[nb];
		opad_ = new unsigned char[nb];
		memset(ipad_, 0, nb);
		memset(opad_, 0, nb);

		if (keylen > nb)
		{
			hash_->hash_string(key, keylen, ipad_);
			memcpy(opad_, ipad_, hashsize()/8);
		}
		else
		{
			memcpy(ipad_, key, keylen);
			memcpy(opad_, key, keylen);
		}

		for (size_t i = 0; i < nb; i++)
		{
			opad_[i] ^= 0x5c;
			ipad_[i] ^= 0x36;
		}
	}

	hmac::~hmac()
	{
		clear();
		zero_memory(ipad_, hash_->blocksize() / 8);
		zero_memory(opad_, hash_->blocksize() / 8);
		delete[] ipad_;
		delete[] opad_;
	}

	void hmac::update(const unsigned char* data, size_t len)
	{
		hash_->update(data, len);
	}

	void hmac::init()
	{
		hash_->init();
		hash_->update(ipad_, blocksize()/8); 
	};

	void hmac::final(unsigned char* hash)
	{
		unsigned char* temp = new unsigned char[hashsize()/8];
		hash_->final(temp);
		hash_->init();
		hash_->update(opad_, blocksize()/8);
		hash_->update(temp, hashsize()/8);
		delete[] temp;
		hash_->final(hash);
	}

	hmac* hmac::clone() const
	{
		hmac* clone = new hmac(*hash_, ipad_, 0);
		size_t nb = blocksize() / 8;
		memcpy(clone->ipad_, ipad_, nb);
		memcpy(clone->opad_, opad_, nb);
		return clone;
	}

	void hmac::clear()
	{
		hash_->clear();
	}

}
