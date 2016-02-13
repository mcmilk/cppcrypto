/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_POLY1305_H
#define CPPCRYPTO_POLY1305_H

#include <stdint.h>
#include <string>
#include <memory>
#include "crypto_hash.h"
#include "poly1305-impl.h"

namespace cppcrypto
{

	class poly1305 : public crypto_hash
	{
	public:
		poly1305(const uint8_t* key, size_t keylen);
		poly1305(const std::string& key);
		virtual ~poly1305();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t keysize() const { return 256; }
		size_t hashsize() const { return 128; }
		size_t blocksize() const { return 128; }
		crypto_hash* clone() const;
		void clear();

	private:
		poly1305(const poly1305&) = delete;
		void operator=(const poly1305&) = delete;
		void construct(const uint8_t* key, size_t keylen);
		void transform(const uint8_t* m, size_t num_blks, bool incomplete);

		aligned_impl_ptr<detail::poly1305_impl, 32> impl_;
		aligned_pod_array<uint8_t, 32, 32> key_;
		aligned_pod_array<uint8_t, 17, 32> r_;
		aligned_pod_array<uint8_t, 17, 32> accumulator_;
		aligned_pod_array<uint8_t, 33, 32> m_;
		size_t pos;
	};

}

#endif
