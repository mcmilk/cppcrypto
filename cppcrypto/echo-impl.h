/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/
#ifndef ECHOIMPL_H
#define ECHOIMPL_H

#include <stdint.h>
#include <emmintrin.h>
#include "alignedarray.h"

namespace cppcrypto
{
	namespace detail
	{

		class echo_impl
		{
		public:
			virtual ~echo_impl() {}
			virtual void transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal) = 0;
			virtual void init(uint64_t* h, uint64_t* salt) = 0;
		};

		class echo_impl_aesni_256 : public echo_impl
		{
		private:
			aligned_pod_array<unsigned char, 6 * 16, 16> MEM_CST;
			aligned_pod_array<unsigned char, 8 * 16 * 16, 16> SHA3_FULL_CNT;
			aligned_pod_array<unsigned char, 4 * 16 * 16, 16> OLDCV;

		public:
			virtual void transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal) override;
			virtual void init(uint64_t* h, uint64_t* salt) override;
		};

		class echo_impl_aesni_512 : public echo_impl
		{
		private:
			aligned_pod_array<unsigned char, 6 * 16, 16> MEM_CST;
			aligned_pod_array<unsigned char, 10 * 16 * 16, 16> SHA3_FULL_CNT;
			aligned_pod_array<unsigned char, 8 * 16 * 16, 16> OLDCV;

		public:
			virtual void transform(uint64_t* h, uint64_t* salt, uint64_t total, bool addedbits, uint64_t addtototal) override;
			virtual void init(uint64_t* h, uint64_t* salt) override;
		};

	}
}
#endif
