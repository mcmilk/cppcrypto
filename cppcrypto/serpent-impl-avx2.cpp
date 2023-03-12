/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "serpent-impl.h"
#include <immintrin.h>
#include "portability.h"
#include <string.h>

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	namespace detail
	{

		namespace
		{

			static inline void sbox0(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;
				r3 = _mm256_xor_si256(r3, r0);
				r1 = _mm256_and_si256(r1, r3);
				r4 = _mm256_xor_si256(r4, r2);
				r1 = _mm256_xor_si256(r1, r0);
				r0 = _mm256_or_si256(r0, r3);
				r0 = _mm256_xor_si256(r0, r4);
				r4 = _mm256_xor_si256(r4, r3);
				r3 = _mm256_xor_si256(r3, r2);
				r2 = _mm256_or_si256(r2, r1);
				r2 = _mm256_xor_si256(r2, r4);
				r4 = _mm256_andnot_si256(r4, ones);
				r4 = _mm256_or_si256(r4, r1);
				r1 = _mm256_xor_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r4);
				r3 = _mm256_or_si256(r3, r0);
				r1 = _mm256_xor_si256(r1, r3);
				r4 = _mm256_xor_si256(r4, r3);
				w0 = r1;
				w1 = r4;
				w2 = r2;
				w3 = r0;
			}

			static inline void sbox1(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
				r0 = _mm256_andnot_si256(r0, ones);
				r2 = _mm256_andnot_si256(r2, ones);
				r4 = r0;
				r0 = _mm256_and_si256(r0, r1);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_or_si256(r0, r3);
				r3 = _mm256_xor_si256(r3, r2);
				r1 = _mm256_xor_si256(r1, r0);
				r0 = _mm256_xor_si256(r0, r4);
				r4 = _mm256_or_si256(r4, r1);
				r1 = _mm256_xor_si256(r1, r3);
				r2 = _mm256_or_si256(r2, r0);
				r2 = _mm256_and_si256(r2, r4);
				r0 = _mm256_xor_si256(r0, r1);
				r1 = _mm256_and_si256(r1, r2);
				r1 = _mm256_xor_si256(r1, r0);
				r0 = _mm256_and_si256(r0, r2);
				r0 = _mm256_xor_si256(r0, r4);
				w0 = r2;
				w1 = r0;
				w2 = r3;
				w3 = r1;
			}

			static inline void sbox2(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r0;
				r0 = _mm256_and_si256(r0, r2);
				r0 = _mm256_xor_si256(r0, r3);
				r2 = _mm256_xor_si256(r2, r1);
				r2 = _mm256_xor_si256(r2, r0);
				r3 = _mm256_or_si256(r3, r4);
				r3 = _mm256_xor_si256(r3, r1);
				r4 = _mm256_xor_si256(r4, r2);
				r1 = r3;
				r3 = _mm256_or_si256(r3, r4);
				r3 = _mm256_xor_si256(r3, r0);
				r0 = _mm256_and_si256(r0, r1);
				r4 = _mm256_xor_si256(r4, r0);
				r1 = _mm256_xor_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r4);
				r4 = _mm256_andnot_si256(r4, ones);
				w0 = r2;
				w1 = r3;
				w2 = r1;
				w3 = r4;
			}

			static inline void sbox3(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r0;
				r0 = _mm256_or_si256(r0, r3);
				r3 = _mm256_xor_si256(r3, r1);
				r1 = _mm256_and_si256(r1, r4);
				r4 = _mm256_xor_si256(r4, r2);
				r2 = _mm256_xor_si256(r2, r3);
				r3 = _mm256_and_si256(r3, r0);
				r4 = _mm256_or_si256(r4, r1);
				r3 = _mm256_xor_si256(r3, r4);
				r0 = _mm256_xor_si256(r0, r1);
				r4 = _mm256_and_si256(r4, r0);
				r1 = _mm256_xor_si256(r1, r3);
				r4 = _mm256_xor_si256(r4, r2);
				r1 = _mm256_or_si256(r1, r0);
				r1 = _mm256_xor_si256(r1, r2);
				r0 = _mm256_xor_si256(r0, r3);
				r2 = r1;
				r1 = _mm256_or_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r0);
				w0 = r1;
				w1 = r2;
				w2 = r3;
				w3 = r4;
			}

			static inline void sbox4(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
				r1 = _mm256_xor_si256(r1, r3);
				r3 = _mm256_andnot_si256(r3, ones);
				r2 = _mm256_xor_si256(r2, r3);
				r3 = _mm256_xor_si256(r3, r0);
				r4 = r1;
				r1 = _mm256_and_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r2);
				r4 = _mm256_xor_si256(r4, r3);
				r0 = _mm256_xor_si256(r0, r4);
				r2 = _mm256_and_si256(r2, r4);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_and_si256(r0, r1);
				r3 = _mm256_xor_si256(r3, r0);
				r4 = _mm256_or_si256(r4, r1);
				r4 = _mm256_xor_si256(r4, r0);
				r0 = _mm256_or_si256(r0, r3);
				r0 = _mm256_xor_si256(r0, r2);
				r2 = _mm256_and_si256(r2, r3);
				r0 = _mm256_andnot_si256(r0, ones);
				r4 = _mm256_xor_si256(r4, r2);
				w0 = r1;
				w1 = r4;
				w2 = r0;
				w3 = r3;
			}

			static inline void sbox5(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;
				r0 = _mm256_xor_si256(r0, r1);
				r1 = _mm256_xor_si256(r1, r3);
				r3 = _mm256_andnot_si256(r3, ones);
				r4 = r1;
				r1 = _mm256_and_si256(r1, r0);
				r2 = _mm256_xor_si256(r2, r3);
				r1 = _mm256_xor_si256(r1, r2);
				r2 = _mm256_or_si256(r2, r4);
				r4 = _mm256_xor_si256(r4, r3);
				r3 = _mm256_and_si256(r3, r1);
				r3 = _mm256_xor_si256(r3, r0);
				r4 = _mm256_xor_si256(r4, r1);
				r4 = _mm256_xor_si256(r4, r2);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_and_si256(r0, r3);
				r2 = _mm256_andnot_si256(r2, ones);
				r0 = _mm256_xor_si256(r0, r4);
				r4 = _mm256_or_si256(r4, r3);
				r2 = _mm256_xor_si256(r2, r4);
				w0 = r1;
				w1 = r3;
				w2 = r0;
				w3 = r2;
			}

			static inline void sbox6(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r3;
				r2 = _mm256_andnot_si256(r2, ones);
				r3 = _mm256_and_si256(r3, r0);
				r0 = _mm256_xor_si256(r0, r4);
				r3 = _mm256_xor_si256(r3, r2);
				r2 = _mm256_or_si256(r2, r4);
				r1 = _mm256_xor_si256(r1, r3);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_or_si256(r0, r1);
				r2 = _mm256_xor_si256(r2, r1);
				r4 = _mm256_xor_si256(r4, r0);
				r0 = _mm256_or_si256(r0, r3);
				r0 = _mm256_xor_si256(r0, r2);
				r4 = _mm256_xor_si256(r4, r3);
				r4 = _mm256_xor_si256(r4, r0);
				r3 = _mm256_andnot_si256(r3, ones);
				r2 = _mm256_and_si256(r2, r4);
				r2 = _mm256_xor_si256(r2, r3);
				w0 = r0;
				w1 = r1;
				w2 = r4;
				w3 = r2;
			}

			static inline void sbox7(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;
				r1 = _mm256_or_si256(r1, r2);
				r1 = _mm256_xor_si256(r1, r3);
				r4 = _mm256_xor_si256(r4, r2);
				r2 = _mm256_xor_si256(r2, r1);
				r3 = _mm256_or_si256(r3, r4);
				r3 = _mm256_and_si256(r3, r0);
				r4 = _mm256_xor_si256(r4, r2);
				r3 = _mm256_xor_si256(r3, r1);
				r1 = _mm256_or_si256(r1, r4);
				r1 = _mm256_xor_si256(r1, r0);
				r0 = _mm256_or_si256(r0, r4);
				r0 = _mm256_xor_si256(r0, r2);
				r1 = _mm256_xor_si256(r1, r4);
				r2 = _mm256_xor_si256(r2, r1);
				r1 = _mm256_and_si256(r1, r0);
				r1 = _mm256_xor_si256(r1, r4);
				r2 = _mm256_andnot_si256(r2, ones);
				r2 = _mm256_or_si256(r2, r0);
				r4 = _mm256_xor_si256(r4, r2);
				w0 = r4;
				w1 = r3;
				w2 = r1;
				w3 = r0;
			}

			static inline void isbox0(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;

				r2 = _mm256_andnot_si256(r2, ones);
				r1 = _mm256_or_si256(r1, r0);
				r4 = _mm256_andnot_si256(r4, ones);
				r1 = _mm256_xor_si256(r1, r2);
				r2 = _mm256_or_si256(r2, r4);
				r1 = _mm256_xor_si256(r1, r3);
				r0 = _mm256_xor_si256(r0, r4);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_and_si256(r0, r3);
				r4 = _mm256_xor_si256(r4, r0);
				r0 = _mm256_or_si256(r0, r1);
				r0 = _mm256_xor_si256(r0, r2);
				r3 = _mm256_xor_si256(r3, r4);
				r2 = _mm256_xor_si256(r2, r1);
				r3 = _mm256_xor_si256(r3, r0);
				r3 = _mm256_xor_si256(r3, r1);
				r2 = _mm256_and_si256(r2, r3);
				r4 = _mm256_xor_si256(r4, r2);
				w0 = r0;
				w1 = r4;
				w2 = r1;
				w3 = r3;
			}

			static inline void isbox1(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r1;

				r1 = _mm256_xor_si256(r1, r3);
				r3 = _mm256_and_si256(r3, r1);
				r4 = _mm256_xor_si256(r4, r2);
				r3 = _mm256_xor_si256(r3, r0);
				r0 = _mm256_or_si256(r0, r1);
				r2 = _mm256_xor_si256(r2, r3);
				r0 = _mm256_xor_si256(r0, r4);
				r0 = _mm256_or_si256(r0, r2);
				r1 = _mm256_xor_si256(r1, r3);
				r0 = _mm256_xor_si256(r0, r1);
				r1 = _mm256_or_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r0);
				r4 = _mm256_andnot_si256(r4, ones);
				r4 = _mm256_xor_si256(r4, r1);
				r1 = _mm256_or_si256(r1, r0);
				r1 = _mm256_xor_si256(r1, r0);
				r1 = _mm256_or_si256(r1, r4);
				r3 = _mm256_xor_si256(r3, r1);
				w0 = r4;
				w1 = r0;
				w2 = r3;
				w3 = r2;
			}

			static inline void isbox2(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4;

				r2 = _mm256_xor_si256(r2, r3);
				r3 = _mm256_xor_si256(r3, r0);
				r4 = r3;
				r3 = _mm256_and_si256(r3, r2);
				r3 = _mm256_xor_si256(r3, r1);
				r1 = _mm256_or_si256(r1, r2);
				r1 = _mm256_xor_si256(r1, r4);
				r4 = _mm256_and_si256(r4, r3);
				r2 = _mm256_xor_si256(r2, r3);
				r4 = _mm256_and_si256(r4, r0);
				r4 = _mm256_xor_si256(r4, r2);
				r2 = _mm256_and_si256(r2, r1);
				r2 = _mm256_or_si256(r2, r0);
				r3 = _mm256_andnot_si256(r3, ones);
				r2 = _mm256_xor_si256(r2, r3);
				r0 = _mm256_xor_si256(r0, r3);
				r0 = _mm256_and_si256(r0, r1);
				r3 = _mm256_xor_si256(r3, r4);
				r3 = _mm256_xor_si256(r3, r0);
				w0 = r1;
				w1 = r4;
				w2 = r2;
				w3 = r3;
			}

			static inline void isbox3(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& /*ones*/)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;

				r2 = _mm256_xor_si256(r2, r1);
				r0 = _mm256_xor_si256(r0, r2);
				r4 = _mm256_and_si256(r4, r2);
				r4 = _mm256_xor_si256(r4, r0);
				r0 = _mm256_and_si256(r0, r1);
				r1 = _mm256_xor_si256(r1, r3);
				r3 = _mm256_or_si256(r3, r4);
				r2 = _mm256_xor_si256(r2, r3);
				r0 = _mm256_xor_si256(r0, r3);
				r1 = _mm256_xor_si256(r1, r4);
				r3 = _mm256_and_si256(r3, r2);
				r3 = _mm256_xor_si256(r3, r1);
				r1 = _mm256_xor_si256(r1, r0);
				r1 = _mm256_or_si256(r1, r2);
				r0 = _mm256_xor_si256(r0, r3);
				r1 = _mm256_xor_si256(r1, r4);
				r0 = _mm256_xor_si256(r0, r1);
				w0 = r2;
				w1 = r1;
				w2 = r3;
				w3 = r0;
			}

			static inline void isbox4(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
				r2 = _mm256_and_si256(r2, r3);
				r2 = _mm256_xor_si256(r2, r1);
				r1 = _mm256_or_si256(r1, r3);
				r1 = _mm256_and_si256(r1, r0);
				r4 = _mm256_xor_si256(r4, r2);
				r4 = _mm256_xor_si256(r4, r1);
				r1 = _mm256_and_si256(r1, r2);
				r0 = _mm256_andnot_si256(r0, ones);
				r3 = _mm256_xor_si256(r3, r4);
				r1 = _mm256_xor_si256(r1, r3);
				r3 = _mm256_and_si256(r3, r0);
				r3 = _mm256_xor_si256(r3, r2);
				r0 = _mm256_xor_si256(r0, r1);
				r2 = _mm256_and_si256(r2, r0);
				r3 = _mm256_xor_si256(r3, r0);
				r2 = _mm256_xor_si256(r2, r4);
				r2 = _mm256_or_si256(r2, r3);
				r3 = _mm256_xor_si256(r3, r0);
				r2 = _mm256_xor_si256(r2, r1);
				w0 = r0;
				w1 = r3;
				w2 = r2;
				w3 = r4;
			}

			static inline void isbox5(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r3;
				r1 = _mm256_andnot_si256(r1, ones);
				r2 = _mm256_xor_si256(r2, r1);
				r3 = _mm256_or_si256(r3, r0);
				r3 = _mm256_xor_si256(r3, r2);
				r2 = _mm256_or_si256(r2, r1);
				r2 = _mm256_and_si256(r2, r0);
				r4 = _mm256_xor_si256(r4, r3);
				r2 = _mm256_xor_si256(r2, r4);
				r4 = _mm256_or_si256(r4, r0);
				r4 = _mm256_xor_si256(r4, r1);
				r1 = _mm256_and_si256(r1, r2);
				r1 = _mm256_xor_si256(r1, r3);
				r4 = _mm256_xor_si256(r4, r2);
				r3 = _mm256_and_si256(r3, r4);
				r4 = _mm256_xor_si256(r4, r1);
				r3 = _mm256_xor_si256(r3, r4);
				r4 = _mm256_andnot_si256(r4, ones);
				r3 = _mm256_xor_si256(r3, r0);
				w0 = r1;
				w1 = r4;
				w2 = r3;
				w3 = r2;
			}

			static inline void isbox6(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
				r0 = _mm256_xor_si256(r0, r2);
				r2 = _mm256_and_si256(r2, r0);
				r4 = _mm256_xor_si256(r4, r3);
				r2 = _mm256_andnot_si256(r2, ones);
				r3 = _mm256_xor_si256(r3, r1);
				r2 = _mm256_xor_si256(r2, r3);
				r4 = _mm256_or_si256(r4, r0);
				r0 = _mm256_xor_si256(r0, r2);
				r3 = _mm256_xor_si256(r3, r4);
				r4 = _mm256_xor_si256(r4, r1);
				r1 = _mm256_and_si256(r1, r3);
				r1 = _mm256_xor_si256(r1, r0);
				r0 = _mm256_xor_si256(r0, r3);
				r0 = _mm256_or_si256(r0, r2);
				r3 = _mm256_xor_si256(r3, r1);
				r4 = _mm256_xor_si256(r4, r0);
				w0 = r1;
				w1 = r2;
				w2 = r4;
				w3 = r3;
			}

			static inline void isbox7(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3, __m256i& ones)
			{
				__m256i r0 = w0, r1 = w1, r2 = w2, r3 = w3, r4 = r2;
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_and_si256(r0, r3);
				r4 = _mm256_or_si256(r4, r3);
				r2 = _mm256_andnot_si256(r2, ones);
				r3 = _mm256_xor_si256(r3, r1);
				r1 = _mm256_or_si256(r1, r0);
				r0 = _mm256_xor_si256(r0, r2);
				r2 = _mm256_and_si256(r2, r4);
				r3 = _mm256_and_si256(r3, r4);
				r1 = _mm256_xor_si256(r1, r2);
				r2 = _mm256_xor_si256(r2, r0);
				r0 = _mm256_or_si256(r0, r2);
				r4 = _mm256_xor_si256(r4, r1);
				r0 = _mm256_xor_si256(r0, r3);
				r3 = _mm256_xor_si256(r3, r4);
				r4 = _mm256_or_si256(r4, r0);
				r3 = _mm256_xor_si256(r3, r2);
				r4 = _mm256_xor_si256(r4, r2);
				w0 = r3;
				w1 = r0;
				w2 = r1;
				w3 = r4;
			}

			static inline __m256i rotate_l32(__m256i arg, int bits)
			{
				return _mm256_or_si256(_mm256_slli_epi32(arg, bits), _mm256_srli_epi32(arg, (32 - bits)));

			}

			static inline __m256i rotate_r32(__m256i arg, int bits)
			{
				return _mm256_or_si256(_mm256_srli_epi32(arg, bits), _mm256_slli_epi32(arg, (32 - bits)));

			}

			static inline void lt(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3)
			{
				w0 = rotate_l32(w0, 13);
				w2 = rotate_l32(w2, 3);
				w1 = _mm256_xor_si256(w1, _mm256_xor_si256(w0, w2));
				w3 = _mm256_xor_si256(w3, _mm256_xor_si256(w2, _mm256_slli_epi32(w0, 3)));
				w1 = rotate_l32(w1, 1);
				w3 = rotate_l32(w3, 7);
				w0 = _mm256_xor_si256(w0, _mm256_xor_si256(w1, w3));
				w2 = _mm256_xor_si256(w2, _mm256_xor_si256(w3, _mm256_slli_epi32(w1, 7)));
				w0 = rotate_l32(w0, 5);
				w2 = rotate_l32(w2, 22);
			}

			static inline void ilt(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3)
			{
				w2 = rotate_r32(w2, 22);
				w0 = rotate_r32(w0, 5);
				w2 = _mm256_xor_si256(w2, _mm256_xor_si256(w3, _mm256_slli_epi32(w1, 7)));
				w0 = _mm256_xor_si256(w0, _mm256_xor_si256(w1, w3));
				w3 = rotate_r32(w3, 7);
				w1 = rotate_r32(w1, 1);
				w3 = _mm256_xor_si256(w3, _mm256_xor_si256(w2, _mm256_slli_epi32(w0, 3)));
				w1 = _mm256_xor_si256(w1, _mm256_xor_si256(w0, w2));
				w2 = rotate_r32(w2, 3);
				w0 = rotate_r32(w0, 13);
			}

			/*
			static inline void Ravx(size_t w, uint32_t* W, __m256i& x0, __m256i& x1, __m256i& x2, __m256i& x3)
			{
				x0 = _mm256_xor_si256(x0, _mm256_set1_epi32(W[w * 4 + 8]));
				x1 = _mm256_xor_si256(x1, _mm256_set1_epi32(W[w * 4 + 9]));
				x2 = _mm256_xor_si256(x2, _mm256_set1_epi32(W[w * 4 + 10]));
				x3 = _mm256_xor_si256(x3, _mm256_set1_epi32(W[w * 4 + 11]));
			}*/

#define Ravx(w,W,x0,x1,x2,x3) \
		x0 = _mm256_xor_si256(x0, _mm256_set1_epi32(W[w * 4 + 8])); \
		x1 = _mm256_xor_si256(x1, _mm256_set1_epi32(W[w * 4 + 9])); \
		x2 = _mm256_xor_si256(x2, _mm256_set1_epi32(W[w * 4 + 10])); \
		x3 = _mm256_xor_si256(x3, _mm256_set1_epi32(W[w * 4 + 11]));

			static inline void transpose(__m256i& w0, __m256i& w1, __m256i& w2, __m256i& w3)
			{
				__m256i t0 = _mm256_unpacklo_epi32(w0, w1);
				__m256i t1 = _mm256_unpacklo_epi32(w2, w3);
				__m256i t2 = _mm256_unpackhi_epi32(w0, w1);
				__m256i t3 = _mm256_unpackhi_epi32(w2, w3);

				w0 = _mm256_unpacklo_epi64(t0, t1);
				w1 = _mm256_unpackhi_epi64(t0, t1);
				w2 = _mm256_unpacklo_epi64(t2, t3);
				w3 = _mm256_unpackhi_epi64(t2, t3);
			}


		}
		void serpent_impl_avx2::init(uint32_t* /* w */)
		{
		}


		void serpent_impl_avx2::decrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* w, cppcrypto::block_cipher& cipher)
		{
			uint32_t W[140];
			memcpy(W, w, sizeof(W));
			size_t x8 = n / 8;
			for (size_t i = 0; i < x8; i++)
			{
				__m256i x0 = _mm256_loadu_si256((const __m256i*)in);
				__m256i x1 = _mm256_loadu_si256((const __m256i*)(in + 32));
				__m256i x2 = _mm256_loadu_si256((const __m256i*)(in + 64));
				__m256i x3 = _mm256_loadu_si256((const __m256i*)(in + 96));

				transpose(x0, x1, x2, x3);

				__m256i ones = _mm256_set1_epi64x(-1);

				Ravx(32, W, x0, x1, x2, x3);
				isbox7(x0, x1, x2, x3, ones);
				Ravx(31, W, x0, x1, x2, x3);

				ilt(x0, x1, x2, x3);
				isbox6(x0, x1, x2, x3, ones);
				Ravx(30, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox5(x0, x1, x2, x3, ones);
				Ravx(29, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox4(x0, x1, x2, x3, ones);
				Ravx(28, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox3(x0, x1, x2, x3, ones);
				Ravx(27, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox2(x0, x1, x2, x3, ones);
				Ravx(26, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox1(x0, x1, x2, x3, ones);
				Ravx(25, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox0(x0, x1, x2, x3, ones);
				Ravx(24, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox7(x0, x1, x2, x3, ones);
				Ravx(23, W, x0, x1, x2, x3);

				ilt(x0, x1, x2, x3);
				isbox6(x0, x1, x2, x3, ones);
				Ravx(22, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox5(x0, x1, x2, x3, ones);
				Ravx(21, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox4(x0, x1, x2, x3, ones);
				Ravx(20, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox3(x0, x1, x2, x3, ones);
				Ravx(19, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox2(x0, x1, x2, x3, ones);
				Ravx(18, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox1(x0, x1, x2, x3, ones);
				Ravx(17, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox0(x0, x1, x2, x3, ones);
				Ravx(16, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox7(x0, x1, x2, x3, ones);
				Ravx(15, W, x0, x1, x2, x3);

				ilt(x0, x1, x2, x3);
				isbox6(x0, x1, x2, x3, ones);
				Ravx(14, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox5(x0, x1, x2, x3, ones);
				Ravx(13, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox4(x0, x1, x2, x3, ones);
				Ravx(12, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox3(x0, x1, x2, x3, ones);
				Ravx(11, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox2(x0, x1, x2, x3, ones);
				Ravx(10, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox1(x0, x1, x2, x3, ones);
				Ravx(9, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox0(x0, x1, x2, x3, ones);
				Ravx(8, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox7(x0, x1, x2, x3, ones);
				Ravx(7, W, x0, x1, x2, x3);

				ilt(x0, x1, x2, x3);
				isbox6(x0, x1, x2, x3, ones);
				Ravx(6, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox5(x0, x1, x2, x3, ones);
				Ravx(5, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox4(x0, x1, x2, x3, ones);
				Ravx(4, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox3(x0, x1, x2, x3, ones);
				Ravx(3, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox2(x0, x1, x2, x3, ones);
				Ravx(2, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox1(x0, x1, x2, x3, ones);
				Ravx(1, W, x0, x1, x2, x3);
				ilt(x0, x1, x2, x3);
				isbox0(x0, x1, x2, x3, ones);
				Ravx(0, W, x0, x1, x2, x3);

				transpose(x0, x1, x2, x3);

				_mm256_storeu_si256((__m256i*)out, x0);
				_mm256_storeu_si256((__m256i*)(out + 32), x1);
				_mm256_storeu_si256((__m256i*)(out + 64), x2);
				_mm256_storeu_si256((__m256i*)(out + 96), x3);

				in += 16 * 8;
				out += 16 * 8;
			}
			n -= x8 * 8;
			for (size_t i = 0; i < n; i++)
			{
				cipher.encrypt_block(in, out);
				in += 16;
				out += 16;
			}
		}

		void serpent_impl_avx2::encrypt_blocks(const unsigned char* in, unsigned char* out, size_t n, uint32_t* w, cppcrypto::block_cipher& cipher)
		{
			uint32_t W[140];
			memcpy(W, w, sizeof(W));
			size_t x8 = n / 8;
			for (size_t i = 0; i < x8; i++)
			{
				__m256i x0 = _mm256_loadu_si256((const __m256i*)in);
				__m256i x1 = _mm256_loadu_si256((const __m256i*)(in + 32));
				__m256i x2 = _mm256_loadu_si256((const __m256i*)(in + 64));
				__m256i x3 = _mm256_loadu_si256((const __m256i*)(in + 96));

				transpose(x0, x1, x2, x3);

				__m256i ones = _mm256_set1_epi64x(-1);
				Ravx(0, W, x0, x1, x2, x3);
				sbox0(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(1, W, x0, x1, x2, x3);
				sbox1(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(2, W, x0, x1, x2, x3);
				sbox2(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(3, W, x0, x1, x2, x3);
				sbox3(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(4, W, x0, x1, x2, x3);
				sbox4(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(5, W, x0, x1, x2, x3);
				sbox5(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(6, W, x0, x1, x2, x3);
				sbox6(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(7, W, x0, x1, x2, x3);
				sbox7(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);

				Ravx(8, W, x0, x1, x2, x3);
				sbox0(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(9, W, x0, x1, x2, x3);
				sbox1(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(10, W, x0, x1, x2, x3);
				sbox2(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(11, W, x0, x1, x2, x3);
				sbox3(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(12, W, x0, x1, x2, x3);
				sbox4(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(13, W, x0, x1, x2, x3);
				sbox5(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(14, W, x0, x1, x2, x3);
				sbox6(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(15, W, x0, x1, x2, x3);
				sbox7(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);

				Ravx(16, W, x0, x1, x2, x3);
				sbox0(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(17, W, x0, x1, x2, x3);
				sbox1(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(18, W, x0, x1, x2, x3);
				sbox2(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(19, W, x0, x1, x2, x3);
				sbox3(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(20, W, x0, x1, x2, x3);
				sbox4(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(21, W, x0, x1, x2, x3);
				sbox5(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(22, W, x0, x1, x2, x3);
				sbox6(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(23, W, x0, x1, x2, x3);
				sbox7(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);

				Ravx(24, W, x0, x1, x2, x3);
				sbox0(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(25, W, x0, x1, x2, x3);
				sbox1(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(26, W, x0, x1, x2, x3);
				sbox2(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(27, W, x0, x1, x2, x3);
				sbox3(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(28, W, x0, x1, x2, x3);
				sbox4(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(29, W, x0, x1, x2, x3);
				sbox5(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(30, W, x0, x1, x2, x3);
				sbox6(x0, x1, x2, x3, ones);
				lt(x0, x1, x2, x3);
				Ravx(31, W, x0, x1, x2, x3);
				sbox7(x0, x1, x2, x3, ones);

				x0 = _mm256_xor_si256(x0, _mm256_set1_epi32(W[136]));
				x1 = _mm256_xor_si256(x1, _mm256_set1_epi32(W[137]));
				x2 = _mm256_xor_si256(x2, _mm256_set1_epi32(W[138]));
				x3 = _mm256_xor_si256(x3, _mm256_set1_epi32(W[139]));

				transpose(x0, x1, x2, x3);

				_mm256_storeu_si256((__m256i*)out, x0);
				_mm256_storeu_si256((__m256i*)(out + 32), x1);
				_mm256_storeu_si256((__m256i*)(out + 64), x2);
				_mm256_storeu_si256((__m256i*)(out + 96), x3);

				in += 16 * 8;
				out += 16 * 8;
			}
			n -= x8 * 8;
			for (size_t i = 0; i < n; i++)
			{
				cipher.encrypt_block(in, out);
				in += 16;
				out += 16;
			}
		}


	}
}
