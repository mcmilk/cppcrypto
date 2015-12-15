/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_WHIRLPOOL_H
#define CPPCRYPTO_WHIRLPOOL_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <memory>

namespace cppcrypto
{

	class whirlpool : public crypto_hash
	{
	public:
		whirlpool();
		~whirlpool();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 512; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new whirlpool; }
		void clear();

	private:
		void transform(void* m, uint64_t num_blks);
		void outputTransform();

		std::function<void(void*, uint64_t)> transfunc;
		aligned_pod_array<uint64_t, 8, 16> h;
		aligned_pod_array<uint8_t, 64, 16> m;
		size_t pos;
		uint64_t total;
	};

}

#endif
