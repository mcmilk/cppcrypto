/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "hkdf.h"
#include <memory.h>
#include "portability.h"
#include <stdexcept>
#include <vector>

namespace cppcrypto
{
	hkdf::hkdf(const crypto_hash& hash)
		: hash_(hash.clone())
	{
	}

	hkdf::~hkdf()
	{
		clear();
	}

	void hkdf::extract(const unsigned char* xts, size_t xts_len, const unsigned char* skm, size_t skm_len, unsigned char* prk, size_t prk_len) const
	{
		if (prk_len != hash_->hashsize() / 8)
			throw std::runtime_error("invalid prk len for hkdf");

		hmac hmac(*hash_);
		if (!xts_len)
			hmac.init(nullptr, 0);
		else
			hmac.init(xts, xts_len);
		hmac.update(skm, skm_len);
		hmac.final(prk);
	}

	void hkdf::set_initial_counter_value(uint8_t counter)
	{
		counter_ = counter;
	}

	void hkdf::expand(const unsigned char* prk, size_t prk_len, const unsigned char* ctxinfo, size_t ctxinfo_len, unsigned char* okm, size_t okm_len) const
	{
		uint8_t counter = counter_;
		size_t hash_bytes = hash_->hashsize() / 8;
		if (okm_len > 255 * hash_bytes)
			throw std::runtime_error("exceeded maximum hkdf length for hash size");
		if (!okm_len)
			throw std::runtime_error("okm_len can't be zero");

		unsigned char* tp = okm;
		
		hmac hmac(*hash_);
		while(okm_len > hash_bytes)
		{
			hmac.init(prk, prk_len);
			if (tp != okm)
			{
				hmac.update(tp, hash_bytes);
				tp += hash_bytes;
			}
			hmac.update(ctxinfo, ctxinfo_len);
			hmac.update(&counter, 1);
			hmac.final(okm);
			okm += hash_bytes;
			okm_len -= hash_bytes;
			counter++;
		}
		if (okm_len > 0)
		{
			std::vector<unsigned char> t;
			t.resize(hash_bytes);
			hmac.init(prk, prk_len);
			if (tp != okm)
				hmac.update(tp, hash_bytes);
			hmac.update(ctxinfo, ctxinfo_len);
			hmac.update(&counter, 1);
			hmac.final(&t[0]);
			memcpy(okm, t.data(), okm_len);
			zero_memory(&t[0], t.size());
		}
	}

	void hkdf::extract_and_expand(const unsigned char* xts, size_t xts_len, const unsigned char* ctxinfo, size_t ctxinfo_len, const unsigned char* skm, size_t skm_len, unsigned char* okm, size_t okm_len) const
	{
		std::vector<unsigned char> prk(hash_->hashsize() / 8);
		extract(xts, xts_len, skm, skm_len, &prk[0], prk.size());
		expand(&prk[0], prk.size(), ctxinfo, ctxinfo_len, okm, okm_len);
		zero_memory(prk.data(), prk.size());
	}

	hkdf* hkdf::clone() const
	{
		return new hkdf(*hash_);
	}

	void hkdf::clear()
	{
		hash_->clear();
	}

	void hkdf::derive_key(const unsigned char* ikm, size_t ikm_len, const unsigned char* random_data, size_t random_data_len, unsigned char* dk, size_t dklen) const
	{
		// random data should be shoved to ctxinfo rather than xts; xts could be a fixed value
		extract_and_expand(nullptr, 0, random_data, random_data_len, ikm, ikm_len, dk, dklen);
	}

}
