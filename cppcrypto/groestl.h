/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_GROESTL_H
#define CPPCRYPTO_GROESTL_H

#include "crypto_hash.h"
#include <functional>
#include <memory>
#include "alignedarray.h"
#include "groestl-impl.h"

namespace cppcrypto
{

	class groestl : public crypto_hash
	{
	public:
		groestl(size_t hashsize);
		~groestl();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return bs; }
		groestl* clone() const override { return new groestl(hs); }
		void clear() override;

	private:
		void transform();
		void outputTransform();

		aligned_pod_array<uint64_t, 16, 32> h;
		aligned_pod_array<unsigned char, 128, 32> m;
		size_t hs;
		size_t bs;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::groestl_impl, 32> impl_;
	};

}

#endif

