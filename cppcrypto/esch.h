/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ESCH_H
#define CPPCRYPTO_ESCH_H

#include "crypto_hash.h"
#include <functional>
#include <memory>
#include "alignedarray.h"
#include "esch-impl.h"

namespace cppcrypto
{

	class esch : public crypto_hash
	{
	public:
		esch(size_t hashsize);
		~esch();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return bs; }
		esch* clone() const override { return new esch(hs); }
		void clear() override;

	private:
		void transform(const unsigned char* data, size_t num_blks, bool lastBlock);

		std::array<uint32_t, 16> H;
		std::array<unsigned char, 128> m;
		size_t hs;
		size_t bs;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::esch_impl, 32> impl_;
	};

}

#endif

