/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
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

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[1] = _mm_blend_epi32(rk[1], temp4, 0x0E);
			temp4 = _mm_srli_si128(temp1, 12);
			rk[2] = _mm_blend_epi32(temp4, temp3, 0x02);

			temp3 = _mm_shuffle_epi32(temp3, 0x00);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);

			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			temp4 = _mm_slli_si128(temp1, 8);
			rk[2] = _mm_blend_epi32(rk[2], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[3] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			temp4 = _mm_slli_si128(temp1, 12);
			rk[3] = _mm_blend_epi32(rk[3], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[4] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			rk[5] = temp1;
			rk[6] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[6] = _mm_blend_epi32(rk[6], temp4, 0x0E);
			temp4 = _mm_srli_si128(temp1, 12);
			rk[7] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[7] = _mm_blend_epi32(rk[7], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[8] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[8] = _mm_blend_epi32(rk[8], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[9] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			rk[10] = temp1;
			rk[11] = temp3;

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

			temp2 = _mm_aeskeygenassist_si128(_mm_slli_si128(temp3, 4), 0x01);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[1] = _mm_blend_epi32(rk[1], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[2] = _mm_blend_epi32(temp4, temp3, 8);

			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[2] = _mm_blend_epi32(rk[2], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[3] = _mm_blend_epi32(temp4, temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[3] = _mm_blend_epi32(rk[3], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[4] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[4] = _mm_blend_epi32(rk[4], temp4, 12);
			rk[5] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[5] = _mm_blend_epi32(rk[5], temp4, 0x0E);
			rk[6] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[6] = _mm_blend_epi32(rk[6], temp3, 0x0E);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			rk[7] = temp1;
			KEY_224_ASSIST_2(&temp1, &temp3);
			rk[8] = temp3;

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[8] = _mm_blend_epi32(rk[8], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[9] = _mm_blend_epi32(temp4, temp3, 8);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[9] = _mm_blend_epi32(rk[9], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[10] = _mm_blend_epi32(temp4, temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[10] = _mm_blend_epi32(rk[10], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[11] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[11] = _mm_blend_epi32(rk[11], temp4, 12);
			rk[12] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[12] = _mm_blend_epi32(rk[12], temp4, 0x0E);
			rk[13] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[13] = _mm_blend_epi32(rk[13], temp3, 0x0E);

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

			temp2 = _mm_aeskeygenassist_si128(_mm_slli_si128(temp3, 4), 0x01);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[1] = _mm_blend_epi32(rk[1], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[2] = _mm_blend_epi32(temp4, temp3, 8);

			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[2] = _mm_blend_epi32(rk[2], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[3] = _mm_blend_epi32(temp4, temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[3] = _mm_blend_epi32(rk[3], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[4] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[4] = _mm_blend_epi32(rk[4], temp4, 12);
			rk[5] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[5] = _mm_blend_epi32(rk[5], temp4, 0x0E);
			rk[6] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[6] = _mm_blend_epi32(rk[6], temp3, 0x0E);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			rk[7] = temp1;
			KEY_224_ASSIST_2(&temp1, &temp3);
			rk[8] = temp3;

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[8] = _mm_blend_epi32(rk[8], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[9] = _mm_blend_epi32(temp4, temp3, 8);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[9] = _mm_blend_epi32(rk[9], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[10] = _mm_blend_epi32(temp4, temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[10] = _mm_blend_epi32(rk[10], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[11] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[11] = _mm_blend_epi32(rk[11], temp4, 12);
			rk[12] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[12] = _mm_blend_epi32(rk[12], temp4, 0x0E);
			rk[13] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[13] = _mm_blend_epi32(rk[13], temp3, 0x0E);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			rk[14] = temp1;
			KEY_224_ASSIST_2(&temp1, &temp3);
			rk[15] = temp3;

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[15] = _mm_blend_epi32(rk[15], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[16] = _mm_blend_epi32(temp4, temp3, 8);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[16] = _mm_blend_epi32(rk[16], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[17] = _mm_blend_epi32(temp4, temp3, 8);


			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[17] = _mm_blend_epi32(rk[17], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[18] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[18] = _mm_blend_epi32(rk[18], temp4, 12);
			rk[19] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x6c);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[19] = _mm_blend_epi32(rk[19], temp4, 0x0E);
			rk[20] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[20] = _mm_blend_epi32(rk[20], temp3, 0x0E);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xd8);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			rk[21] = temp1;
			KEY_224_ASSIST_2(&temp1, &temp3);
			rk[22] = temp3;

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0xab);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[22] = _mm_blend_epi32(rk[22], temp4, 8);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[23] = _mm_blend_epi32(temp4, temp3, 8);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 12);
			rk[23] = _mm_blend_epi32(rk[23], temp4, 8);
			temp4 = _mm_srli_si128(temp3, 4);
			rk[24] = _mm_blend_epi32(temp4, temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4d);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[24] = _mm_blend_epi32(rk[24], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[25] = _mm_blend_epi32(temp4, temp3, 4);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp4 = _mm_slli_si128(temp3, 8);
			rk[25] = _mm_blend_epi32(rk[25], temp4, 12);
			rk[26] = _mm_srli_si128(temp3, 8);

			temp3 = _mm_slli_si128(temp3, 4);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x9a);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[26] = _mm_blend_epi32(rk[26], temp4, 0x0E);
			rk[27] = _mm_srli_si128(temp1, 12);
			KEY_224_ASSIST_2(&temp1, &temp3);
			temp3 = _mm_slli_si128(temp3, 4);
			rk[27] = _mm_blend_epi32(rk[27], temp3, 0x0E);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x2f);
			temp3 = _mm_srli_si128(temp3, 4);
			KEY_224_ASSIST_1(&temp1, &temp2);
			rk[28] = temp1;
			KEY_224_ASSIST_2(&temp1, &temp3);
			rk[29] = temp3;

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

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[1] = _mm_blend_epi32(rk[1], temp4, 0x0E);
			temp4 = _mm_srli_si128(temp1, 12);
			rk[2] = _mm_blend_epi32(temp4, temp3, 0x02);

			temp3 = _mm_shuffle_epi32(temp3, 0x00);
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);

			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			temp4 = _mm_slli_si128(temp1, 8);
			rk[2] = _mm_blend_epi32(rk[2], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[3] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			temp4 = _mm_slli_si128(temp1, 12);
			rk[3] = _mm_blend_epi32(rk[3], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[4] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);

			rk[5] = temp1;
			rk[6] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[6] = _mm_blend_epi32(rk[6], temp4, 0x0E);
			// 0
			temp4 = _mm_srli_si128(temp1, 12);
			rk[7] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[7] = _mm_blend_epi32(rk[7], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[8] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[8] = _mm_blend_epi32(rk[8], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[9] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			rk[10] = temp1;
			rk[11] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1B);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[11] = _mm_blend_epi32(temp4, rk[11], 0x01);

			// ... 2
			temp4 = _mm_srli_si128(temp1, 12);
			rk[12] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[12] = _mm_blend_epi32(rk[12], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[13] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x6c);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[13] = _mm_blend_epi32(rk[13], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[14] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xd8);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			rk[15] = temp1;
			rk[16] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xab);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[16] = _mm_blend_epi32(temp4, rk[16], 0x01);

			// ... 3
			temp4 = _mm_srli_si128(temp1, 12);
			rk[17] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4d);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[17] = _mm_blend_epi32(rk[17], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[18] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x9a);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[18] = _mm_blend_epi32(rk[18], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[19] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x2f);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			rk[20] = temp1;
			rk[21] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x5e);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[21] = _mm_blend_epi32(temp4, rk[21], 0x01);

			// ... 4
			temp4 = _mm_srli_si128(temp1, 12);
			rk[22] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xbc);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[22] = _mm_blend_epi32(rk[22], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[23] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x63);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[23] = _mm_blend_epi32(rk[23], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[24] = _mm_blend_epi32(temp4, temp3, 8);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xc6);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			rk[25] = temp1;
			rk[26] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x97);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 4);
			rk[26] = _mm_blend_epi32(temp4, rk[26], 0x01);

			// ... 5
			temp4 = _mm_srli_si128(temp1, 12);
			rk[27] = _mm_blend_epi32(temp4, temp3, 2);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x35);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 8);
			rk[27] = _mm_blend_epi32(rk[27], temp4, 12);
			temp4 = _mm_srli_si128(temp1, 8);
			rk[28] = _mm_blend_epi32(temp4, temp3, 4);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x6a);
			KEY_160_ASSIST(&temp1, &temp2, &temp3);
			temp4 = _mm_slli_si128(temp1, 12);
			rk[28] = _mm_blend_epi32(rk[28], temp4, 0x08);
			temp4 = _mm_srli_si128(temp1, 4);
			rk[29] = _mm_blend_epi32(temp4, temp3, 8);

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

	}
}
