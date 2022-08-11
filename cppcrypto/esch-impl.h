/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef ESCHIMPL_H
#define ESCHIMPL_H

#include <stdint.h>
#include <immintrin.h>
#include "alignedarray.h"

namespace cppcrypto
{
	namespace detail
	{

		class esch_impl
		{
		public:
			virtual ~esch_impl() {}
			virtual void transform(const unsigned char* m, size_t num_blks, bool lastBlock) = 0;
			virtual void final(unsigned char* hash, unsigned char* m, uint64_t& total, size_t& pos) = 0;
			virtual void init() = 0;
		};

		class esch_avx2_impl : public esch_impl
		{
		public:
			esch_avx2_impl();
			virtual void init() override;

		protected:
			const __m128i r16_128;
			const __m256i r16_256;
			__m256i Hc;
			__m256i HHx;
			__m256i HHy;
		};

		class esch256_avx2_impl : public esch_avx2_impl
		{
		public:
			esch256_avx2_impl();
			virtual void transform(const unsigned char* m, size_t num_blks, bool lastBlock) override;
			virtual void final(unsigned char* hash, unsigned char* m, uint64_t& total, size_t& pos) override;

		private:
			const __m256i mask1;
			const __m256i mask2;
		};

		class esch384_avx2_impl : public esch_avx2_impl
		{
		public:
			virtual void transform(const unsigned char* m, size_t num_blks, bool lastBlock) override;
			virtual void final(unsigned char* hash, unsigned char* m, uint64_t& total, size_t& pos) override;
		};

	}
}
#endif
