#ifndef GROESTLIMPL_H
#define GROESTLIMPL_H

#include <stdint.h>
#include <emmintrin.h>

namespace cppcrypto
{
	namespace detail
	{

		class groestl_impl
		{
		public:
			virtual ~groestl_impl() {}
			virtual void INIT(uint64_t* h) = 0;
			virtual void TF(uint64_t* h, uint64_t* m) = 0;
			virtual void OF(uint64_t* h) = 0;
		};

		class groestl_impl_ssse3_256 : public groestl_impl
		{
		private:
			__m128i SSSE3_ROUND_CONST_Lx;
			__m128i SSSE3_ROUND_CONST_L0[10];
			__m128i SSSEE3_ROUND_CONST_L7[10];
			__m128i SSSE3_TRANSP_MASK;
			__m128i SSSE3_SUBSH_MASK[8];
			__m128i ALL_0F;
			__m128i ALL_15;
			__m128i SSSE3_ALL_1B;
			__m128i ALL_63;
			__m128i VPERM_IPT[2];
			__m128i VPERM_OPT[2];
			__m128i VPERM_INV[2];
			__m128i VPERM_SB1[2];
			__m128i VPERM_SB2[2];
			__m128i VPERM_SB4[2];

		public:
			groestl_impl_ssse3_256();

			void INIT(uint64_t* h) override;
			void TF(uint64_t* h, uint64_t* m) override;
			void OF(uint64_t* h) override;
		};

		class groestl_impl_ssse3_512 : public groestl_impl
		{
		private:
			__m128i SSSE3_ROUND_CONST_P[14];
			__m128i SSSE3_ROUND_CONST_Q[14];
			__m128i SSSE3_TRANSP_MASK;
			__m128i SSSE3_SUBSH_MASK[8];
			__m128i ALL_0F;
			__m128i ALL_15;
			__m128i SSSE3_ALL_1B;
			__m128i ALL_63;
			__m128i SSSE3_ALL_FF;
			__m128i VPERM_IPT[2];
			__m128i VPERM_OPT[2];
			__m128i VPERM_INV[2];
			__m128i VPERM_SB1[2];
			__m128i VPERM_SB2[2];
			__m128i VPERM_SB4[2];

		public:
			groestl_impl_ssse3_512();

			void INIT(uint64_t* h);
			void TF(uint64_t* h, uint64_t* m);
			void OF(uint64_t* h);
		};

		class groestl_impl_aesni_256 : public groestl_impl
		{
		private:
			__m128i ROUND_CONST_Lx;
			__m128i ROUND_CONST_L0[10];
			__m128i ROUND_CONST_L7[10];
			__m128i TRANSP_MASK;
			__m128i SUBSH_MASK[8];
			__m128i ALL_1B;

		public:
			groestl_impl_aesni_256();

			void INIT(uint64_t* h);
			void TF(uint64_t* h, uint64_t* m);
			void OF(uint64_t* h);
		};

		class groestl_impl_aesni_512 : public groestl_impl
		{
		private:
			__m128i ROUND_CONST_P[14];
			__m128i ROUND_CONST_Q[14];
			__m128i TRANSP_MASK;
			__m128i SUBSH_MASK[8];
			__m128i ALL_1B;
			__m128i ALL_FF;

		public:
			groestl_impl_aesni_512();

			void INIT(uint64_t* h) override;
			void TF(uint64_t* h, uint64_t* m) override;
			void OF(uint64_t* h) override;
		};

	}
}
#endif
