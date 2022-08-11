/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ECHO_H
#define CPPCRYPTO_ECHO_H

#include "crypto_hash.h"
#include <functional>
#include <memory>
#include "alignedarray.h"
#include "echo-impl.h"

namespace cppcrypto
{

	class echo : public crypto_hash
	{
	public:
		echo(size_t hashsize, const unsigned char* salt = nullptr, size_t saltlen = 0);
		~echo();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return bs; }
		echo* clone() const override;
		void clear() override;

	private:
		void transform(bool addedbits, uint64_t addtototal);
		void validate_salt_length(size_t saltlen) const;

		size_t hs;
		size_t bs;
		aligned_pod_array<uint64_t, 32, 16> h;
		aligned_pod_array<uint64_t, 2, 16> salt;
		unsigned char* m;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::echo_impl, 32> impl_;
	};

}

#endif

