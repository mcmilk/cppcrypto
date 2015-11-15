/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "rijndael-impl.h"
#include <xmmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <memory.h>

namespace cppcrypto
{
	namespace detail
	{

		static inline void KEY_160_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3)
		{
			__m128i temp4;
			*temp2 = _mm_shuffle_epi32(*temp2, 0x55);
			temp4 = _mm_slli_si128(*temp1, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			*temp1 = _mm_xor_si128(*temp1, *temp2);
			*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
			*temp3 = _mm_xor_si128(*temp3, *temp2);
		}

#define KEYGEN160STEP(idx, rc, sl, sr, b1, b2) \
	temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
	KEY_160_ASSIST(&temp1, &temp2, &temp3); \
	temp4 = _mm_slli_si128(temp1, sl); \
	rk[idx] = _mm_blend_epi32(rk[idx], temp4, b1); \
	temp4 = _mm_srli_si128(temp1, sr); \
	rk[idx+1] = _mm_blend_epi32(temp4, temp3, b2);

#define KEYGEN160STEPA(idx, rc) \
	temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
	KEY_160_ASSIST(&temp1, &temp2, &temp3); \
	rk[idx] = temp1; \
	rk[idx+1] = temp3;


#define KEYGEN224STEPA(idx, rc) \
		temp3 = _mm_slli_si128(temp3, 4); \
		temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
		temp3 = _mm_srli_si128(temp3, 4); \
		KEY_224_ASSIST_1(&temp1, &temp2); \
		temp4 = _mm_slli_si128(temp1, 12); \
		rk[idx] = _mm_blend_epi32(rk[idx], temp4, 8); \
		temp4 = _mm_srli_si128(temp1, 4); \
		rk[idx+1] = _mm_blend_epi32(temp4, temp3, 8); \
		KEY_224_ASSIST_2(&temp1, &temp3); \
		temp4 = _mm_slli_si128(temp3, 12); \
		rk[idx+1] = _mm_blend_epi32(rk[idx+1], temp4, 8); \
		temp4 = _mm_srli_si128(temp3, 4); \
		rk[idx+2] = _mm_blend_epi32(temp4, temp3, 8);

#define KEYGEN224STEPB(idx, rc) \
		temp3 = _mm_slli_si128(temp3, 4); \
		temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
		temp3 = _mm_srli_si128(temp3, 4); \
		KEY_224_ASSIST_1(&temp1, &temp2); \
		temp4 = _mm_slli_si128(temp1, 8); \
		rk[idx] = _mm_blend_epi32(rk[idx], temp4, 12); \
		temp4 = _mm_srli_si128(temp1, 8); \
		rk[idx+1] = _mm_blend_epi32(temp4, temp3, 4); \
		KEY_224_ASSIST_2(&temp1, &temp3); \
		temp4 = _mm_slli_si128(temp3, 8); \
		rk[idx+1] = _mm_blend_epi32(rk[idx+1], temp4, 12); \
		rk[idx+2] = _mm_srli_si128(temp3, 8);

#define KEYGEN224STEPC(idx, rc) \
		temp3 = _mm_slli_si128(temp3, 4); \
		temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
		temp3 = _mm_srli_si128(temp3, 4); \
		KEY_224_ASSIST_1(&temp1, &temp2); \
		temp4 = _mm_slli_si128(temp1, 4); \
		rk[idx] = _mm_blend_epi32(rk[idx], temp4, 0x0E); \
		rk[idx+1] = _mm_srli_si128(temp1, 12); \
		KEY_224_ASSIST_2(&temp1, &temp3); \
		temp3 = _mm_slli_si128(temp3, 4); \
		rk[idx+1] = _mm_blend_epi32(rk[idx+1], temp3, 0x0E);

#define KEYGEN224STEPD(idx, rc) \
		temp2 = _mm_aeskeygenassist_si128(temp3, rc); \
		temp3 = _mm_srli_si128(temp3, 4); \
		KEY_224_ASSIST_1(&temp1, &temp2); \
		rk[idx] = temp1; \
		KEY_224_ASSIST_2(&temp1, &temp3); \
		rk[idx+1] = temp3;

		bool rijndael128_160_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 160 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));

			rk[0] = temp1;
			rk[1] = temp3;
			__m128i temp2, temp4;
			temp3 = _mm_shuffle_epi32(temp3, 0x00);

			KEYGEN160STEP(1, 0x01, 4, 12, 0x0E, 0x02);
			//temp3 = _mm_shuffle_epi32(temp3, 0x00);
			KEYGEN160STEP(2, 0x02, 8, 8, 12, 4);
			KEYGEN160STEP(3, 0x04, 12, 4, 8, 8);
			KEYGEN160STEPA(5, 0x08);
			KEYGEN160STEP(6, 0x10, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(7, 0x20, 8, 8, 12, 4);
			KEYGEN160STEP(8, 0x40, 12, 4, 8, 8);
			KEYGEN160STEPA(10, 0x80);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1B);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[11] = _mm_blend_epi32(temp4, rk[11], 0x01);

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[11]);
				std::swap(rk[1], rk[10]);
				std::swap(rk[2], rk[9]);
				std::swap(rk[3], rk[8]);
				std::swap(rk[4], rk[7]);
				std::swap(rk[5], rk[6]);

				rk[1] = _mm_aesimc_si128(rk[1]);
				rk[2] = _mm_aesimc_si128(rk[2]);
				rk[3] = _mm_aesimc_si128(rk[3]);
				rk[4] = _mm_aesimc_si128(rk[4]);
				rk[5] = _mm_aesimc_si128(rk[5]);
				rk[6] = _mm_aesimc_si128(rk[6]);
				rk[7] = _mm_aesimc_si128(rk[7]);
				rk[8] = _mm_aesimc_si128(rk[8]);
				rk[9] = _mm_aesimc_si128(rk[9]);
				rk[10] = _mm_aesimc_si128(rk[10]);
			}

			return true;
		}

		static inline void KEY_224_ASSIST_1(__m128i* temp1, __m128i * temp2)
		{
			__m128i temp4;
			*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
			temp4 = _mm_slli_si128(*temp1, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp1 = _mm_xor_si128(*temp1, temp4);
			*temp1 = _mm_xor_si128(*temp1, *temp2);
		}

		static inline void KEY_224_ASSIST_2(__m128i* temp1, __m128i * temp3)
		{
			__m128i temp2, temp4;
			temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
			temp2 = _mm_shuffle_epi32(temp4, 0xaa);
			temp4 = _mm_slli_si128(*temp3, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			*temp3 = _mm_xor_si128(*temp3, temp2);
		}

		bool rijndael128_224_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 224 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));
			__m128i temp2, temp4;
			rk[0] = temp1;
			rk[1] = temp3;

			KEYGEN224STEPA(1, 0x01);
			KEYGEN224STEPB(3, 0x02);
			KEYGEN224STEPC(5, 0x04);
			KEYGEN224STEPD(7, 0x08);
			KEYGEN224STEPA(8, 0x10);
			KEYGEN224STEPB(10, 0x20);
			KEYGEN224STEPC(12, 0x40);

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[13]);
				std::swap(rk[1], rk[12]);
				std::swap(rk[2], rk[11]);
				std::swap(rk[3], rk[10]);
				std::swap(rk[4], rk[9]);
				std::swap(rk[5], rk[8]);
				std::swap(rk[6], rk[7]);

				rk[1] = _mm_aesimc_si128(rk[1]);
				rk[2] = _mm_aesimc_si128(rk[2]);
				rk[3] = _mm_aesimc_si128(rk[3]);
				rk[4] = _mm_aesimc_si128(rk[4]);
				rk[5] = _mm_aesimc_si128(rk[5]);
				rk[6] = _mm_aesimc_si128(rk[6]);
				rk[7] = _mm_aesimc_si128(rk[7]);
				rk[8] = _mm_aesimc_si128(rk[8]);
				rk[9] = _mm_aesimc_si128(rk[9]);
				rk[10] = _mm_aesimc_si128(rk[10]);
				rk[11] = _mm_aesimc_si128(rk[11]);
				rk[12] = _mm_aesimc_si128(rk[12]);
			}

			return true;
		}

		bool rijndael256_224_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 224 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));
			__m128i temp2, temp4;
			rk[0] = temp1;
			rk[1] = temp3;

			KEYGEN224STEPA(1, 0x01);
			KEYGEN224STEPB(3, 0x02);
			KEYGEN224STEPC(5, 0x04);
			KEYGEN224STEPD(7, 0x08);
			KEYGEN224STEPA(8, 0x10);
			KEYGEN224STEPB(10, 0x20);
			KEYGEN224STEPC(12, 0x40);
			KEYGEN224STEPD(14, 0x80);
			KEYGEN224STEPA(15, 0x1b);
			KEYGEN224STEPB(17, 0x36);
			KEYGEN224STEPC(19, 0x6c);
			KEYGEN224STEPD(21, 0xd8);
			KEYGEN224STEPA(22, 0xab);
			KEYGEN224STEPB(24, 0x4d);
			KEYGEN224STEPC(26, 0x9a);
			KEYGEN224STEPD(28, 0x2f);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x5e);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[29] = _mm_blend_epi32(rk[29], temp4, 8);

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[28]);
				std::swap(rk[1], rk[29]);
				std::swap(rk[2], rk[26]);
				std::swap(rk[3], rk[27]);
				std::swap(rk[4], rk[24]);
				std::swap(rk[5], rk[25]);
				std::swap(rk[6], rk[22]);
				std::swap(rk[7], rk[23]);
				std::swap(rk[8], rk[20]);
				std::swap(rk[9], rk[21]);
				std::swap(rk[10], rk[18]);
				std::swap(rk[11], rk[19]);
				std::swap(rk[12], rk[16]);
				std::swap(rk[13], rk[17]);

				for (int i = 2; i < 28; i++)
					rk[i] = _mm_aesimc_si128(rk[i]);
			}

			return true;
		}

		bool rijndael256_160_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 160 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));

			rk[0] = temp1;
			rk[1] = temp3;
			__m128i temp2, temp4;
			temp3 = _mm_shuffle_epi32(temp3, 0x00);

			KEYGEN160STEP(1, 0x01, 4, 12, 0x0E, 0x02);
			//temp3 = _mm_shuffle_epi32(temp3, 0x00);
			KEYGEN160STEP(2, 0x02, 8, 8, 12, 4);
			KEYGEN160STEP(3, 0x04, 12, 4, 8, 8);
			KEYGEN160STEPA(5, 0x08);
			KEYGEN160STEP(6, 0x10, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(7, 0x20, 8, 8, 12, 4);
			KEYGEN160STEP(8, 0x40, 12, 4, 8, 8);
			KEYGEN160STEPA(10, 0x80);
			KEYGEN160STEP(11, 0x1B, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(12, 0x36, 8, 8, 12, 4);
			KEYGEN160STEP(13, 0x6c, 12, 4, 8, 8);
			KEYGEN160STEPA(15, 0xd8);
			KEYGEN160STEP(16, 0xab, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(17, 0x4d, 8, 8, 12, 4);
			KEYGEN160STEP(18, 0x9a, 12, 4, 8, 8);
			KEYGEN160STEPA(20, 0x2f);
			KEYGEN160STEP(21, 0x5e, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(22, 0xbc, 8, 8, 12, 4);
			KEYGEN160STEP(23, 0x63, 12, 4, 8, 8);
			KEYGEN160STEPA(25, 0xc6);
			KEYGEN160STEP(26, 0x97, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(27, 0x35, 8, 8, 12, 4);
			KEYGEN160STEP(28, 0x6a, 12, 4, 8, 8);

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[28]);
				std::swap(rk[1], rk[29]);
				std::swap(rk[2], rk[26]);
				std::swap(rk[3], rk[27]);
				std::swap(rk[4], rk[24]);
				std::swap(rk[5], rk[25]);
				std::swap(rk[6], rk[22]);
				std::swap(rk[7], rk[23]);
				std::swap(rk[8], rk[20]);
				std::swap(rk[9], rk[21]);
				std::swap(rk[10], rk[18]);
				std::swap(rk[11], rk[19]);
				std::swap(rk[12], rk[16]);
				std::swap(rk[13], rk[17]);

				for (int i = 2; i < 28; i++)
					rk[i] = _mm_aesimc_si128(rk[i]);
			}

			return true;
		}

		bool rijndael192_160_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 160 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));

			rk[0] = temp1;
			rk[1] = temp3;
			__m128i temp2, temp4;
			temp3 = _mm_shuffle_epi32(temp3, 0x00);

			KEYGEN160STEP(1, 0x01, 4, 12, 0x0E, 0x02);
			//temp3 = _mm_shuffle_epi32(temp3, 0x00);
			KEYGEN160STEP(2, 0x02, 8, 8, 12, 4);
			KEYGEN160STEP(3, 0x04, 12, 4, 8, 8);
			KEYGEN160STEPA(5, 0x08);
			KEYGEN160STEP(6, 0x10, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(7, 0x20, 8, 8, 12, 4);
			KEYGEN160STEP(8, 0x40, 12, 4, 8, 8);
			KEYGEN160STEPA(10, 0x80);
			KEYGEN160STEP(11, 0x1B, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(12, 0x36, 8, 8, 12, 4);
			KEYGEN160STEP(13, 0x6c, 12, 4, 8, 8);
			KEYGEN160STEPA(15, 0xd8);
			KEYGEN160STEP(16, 0xab, 4, 12, 0x0E, 0x02);
			KEYGEN160STEP(17, 0x4d, 8, 8, 12, 4);
			KEYGEN160STEP(18, 0x9a, 12, 4, 8, 8);

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[18]);
				std::swap(rk[2], rk[17]);
				std::swap(rk[3], rk[15]);
				std::swap(rk[5], rk[14]);
				std::swap(rk[6], rk[12]);
				std::swap(rk[8], rk[11]);

				__m128i t1 = _mm_blend_epi32(rk[16], rk[19], 3); // rk[1]
				rk[19] = rk[1];
				rk[1] = t1;
				t1 = _mm_blend_epi32(rk[13], rk[16], 3); // rk[4]
				rk[16] = _mm_blend_epi32(rk[19], rk[4], 3);
				__m128i t2 = _mm_blend_epi32(rk[4], rk[7], 3); // rk[13]
				rk[4] = t1;
				t1 = _mm_blend_epi32(rk[10], rk[13], 3); // rk[7]
				rk[10] = _mm_blend_epi32(rk[7], rk[10], 3);
				rk[7] = t1;
				rk[13] = t2;

				for (int i = 2; i < 18; i++)
					rk[i] = _mm_aesimc_si128(rk[i]);
				t2 = _mm_aesimc_si128(rk[1]);
				rk[1] = _mm_blend_epi32(t2, rk[1], 3);
			}

			return true;
		}

		inline static __m128i mm_blend_swap_int64(__m128i t1, __m128i t2, const int mask)
		{
			__m128d f1 = _mm_castsi128_pd(t1);
			__m128d f2 = _mm_castsi128_pd(t2);
			f1 = _mm_blend_pd(f2, f1, 1);
			f1 = _mm_shuffle_pd(f1, f1, 1);
			return _mm_castpd_si128(f1);
		}

		bool rijndael192_224_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 224 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));
			__m128i temp2, temp4;
			rk[0] = temp1;
			rk[1] = temp3;

			KEYGEN224STEPA(1, 0x01);
			KEYGEN224STEPB(3, 0x02);
			KEYGEN224STEPC(5, 0x04);
			KEYGEN224STEPD(7, 0x08);
			KEYGEN224STEPA(8, 0x10);
			KEYGEN224STEPB(10, 0x20);
			KEYGEN224STEPC(12, 0x40);
			KEYGEN224STEPD(14, 0x80);
			KEYGEN224STEPA(15, 0x1b);
			KEYGEN224STEPB(17, 0x36);
			KEYGEN224STEPC(19, 0x6c);

			if (direction == block_cipher::decryption)
			{
				__m128i t1 = mm_blend_swap_int64(rk[1], rk[0], 3); // rk[20]
				__m128i t2 = mm_blend_swap_int64(rk[0], rk[2], 3); // rk[19]
				rk[0] = mm_blend_swap_int64(rk[20], rk[19], 3);
				__m128i t3 = mm_blend_swap_int64(rk[18], rk[20], 3); // rk[1]
				rk[20] = t1;
				t1 = mm_blend_swap_int64(rk[2], rk[1], 3); // rk[18]
				rk[1] = t3;
				rk[2] = mm_blend_swap_int64(rk[19], rk[18], 3);
				rk[19] = t2;
				rk[18] = t1;
				t1 = mm_blend_swap_int64(rk[17], rk[16], 3); // rk[3]
				t2 = mm_blend_swap_int64(rk[15], rk[17], 3); // rk[4]
				rk[17] = mm_blend_swap_int64(rk[4], rk[3], 3);
				t3 = mm_blend_swap_int64(rk[16], rk[15], 3); // rk[5]
				rk[16] = mm_blend_swap_int64(rk[3], rk[5], 3);
				rk[15] = mm_blend_swap_int64(rk[5], rk[4], 3);
				rk[3] = t1;
				rk[4] = t2;
				rk[5] = t3;
				t1 = mm_blend_swap_int64(rk[14], rk[13], 3); // rk[6]
				t2 = mm_blend_swap_int64(rk[12], rk[14], 3); // rk[7]
				t3 = mm_blend_swap_int64(rk[13], rk[12], 3); // rk[8]
				rk[14] = mm_blend_swap_int64(rk[7], rk[6], 3);
				rk[13] = mm_blend_swap_int64(rk[6], rk[8], 3);
				rk[12] = mm_blend_swap_int64(rk[8], rk[7], 3);
				rk[6] = t1;
				rk[7] = t2;
				rk[8] = t3;
				t1 = mm_blend_swap_int64(rk[11], rk[10], 3); // rk[9]
				t2 = mm_blend_swap_int64(rk[9], rk[11], 3); // rk[10]
				rk[11] = mm_blend_swap_int64(rk[10], rk[9], 3);
				rk[10] = t2;
				rk[9] = t1;

				for (int i = 2; i < 19; i++)
					rk[i] = _mm_aesimc_si128(rk[i]);
				t2 = _mm_aesimc_si128(rk[1]);
				rk[1] = _mm_blend_epi32(t2, rk[1], 3);
				t2 = _mm_aesimc_si128(rk[19]);
				rk[19] = _mm_blend_epi32(rk[19], t2, 3);
			}

			return true;
		}

	}
}
