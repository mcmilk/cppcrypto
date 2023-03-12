/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "hmac.h"
#include <memory.h>
#include "portability.h"

namespace cppcrypto
{
	hmac::hmac(const crypto_hash& hash)
		: hash_(hash.clone()), ipad_(blocksize() / 8, 0), opad_(blocksize() / 8, 0), keylen_(hashsize() / 8)
	{
	}

	hmac::~hmac()
	{
		clear();
	}

	void hmac::init(const unsigned char* key, size_t keylen)
	{
		clear();
		keylen_ = keylen;
		size_t nb = blocksize() / 8;
		memset(&ipad_[0], 0, nb);
		memset(&opad_[0], 0, nb);

		if (keylen > nb)
		{
			hash_->hash_string(key, keylen, &ipad_[0]);
			memcpy(&opad_[0], ipad_.data(), hashsize() / 8);
		}
		else
		{
			memcpy(&ipad_[0], key, keylen);
			memcpy(&opad_[0], key, keylen);
		}

		for (size_t i = 0; i < nb; i++)
		{
			opad_[i] ^= 0x5c;
			ipad_[i] ^= 0x36;
		}
		hash_->init();
		hash_->update(ipad_.data(), blocksize() / 8);
	}

	void hmac::update(const unsigned char* data, size_t len)
	{
		hash_->update(data, len);
	}

	void hmac::do_final(unsigned char* hash)
	{
		hash_->final(hash);
		hash_->init();
		hash_->update(opad_.data(), blocksize() / 8);
		hash_->update(hash, hashsize() / 8);
		hash_->final(hash);
	}

	hmac* hmac::clone() const
	{
		hmac* clone = new hmac(*hash_);
		clone->keylen_ = keylen_;
		clone->ipad_ = ipad_;
		clone->opad_ = ipad_;
		return clone;
	}

	void hmac::clear()
	{
		hash_->clear();
		if (!ipad_.empty())
		{
			zero_memory(&ipad_[0], ipad_.size());
		}
		if (!opad_.empty())
		{
			zero_memory(&opad_[0], opad_.size());
		}
	}

	size_t hmac::blocksize() const
	{
		if (hash_->blocksize() >= hash_->hashsize())
			return hash_->blocksize();

		// HMAC requires block size greater than hashsize
		// If hashsize of the underlying hash is greater than blocksize,
		// use blocksize of SHA-256 or SHA-512 for HMAC, depending on hashsize.
		// If hashsize is still greater than blocksize, use hashsize as blocksize.
		size_t blocks = static_cast<size_t>(hash_->hashsize() <= 256 ? 512 : 1024);
		size_t hashs = hash_->hashsize();
		return hashs > blocks ? hashs : blocks;

	}

}
