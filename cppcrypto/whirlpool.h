/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_WHIRLPOOL_H
#define CPPCRYPTO_WHIRLPOOL_H

#include "crypto_hash.h"
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

		int hashbitlen() const { return 512; }

	private:
		void transform();
		void outputTransform();

		std::function<void()> transfunc;
		uint64_t* h;
		uint8_t* m;
		size_t pos;
		uint64_t total;
	};

}

#endif