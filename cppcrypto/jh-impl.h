#ifndef CPPCRYPTO_JHIMPL_H
#define CPPCRYPTO_JHIMPL_H

#include <emmintrin.h>
#include <stdint.h>

namespace cppcrypto
{
	namespace detail
	{

		class jh_impl
		{
		public:
			virtual ~jh_impl() {}
			virtual void init(size_t bitlen) = 0;
			virtual void F8(const unsigned char* buffer) = 0;
			virtual void output(unsigned char* hash, size_t bitlen) = 0;
		};

		class jh_impl_sse2 : public jh_impl
		{
		public:
			virtual void init(size_t bitlen);
			virtual void F8(const unsigned char* buffer);
			virtual void output(unsigned char* hash, size_t bitlen);
		private:
			__m128i x0, x1, x2, x3, x4, x5, x6, x7;
		};
	}
}
#endif
