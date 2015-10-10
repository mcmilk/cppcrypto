/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#include "rijndael-impl.h"
#include <wmmintrin.h>
#include <smmintrin.h>
#include <memory.h>

namespace cppcrypto
{
	namespace detail
	{
		static inline __m128i aes128_keyexpand(__m128i key)
		{
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			return _mm_xor_si128(key, _mm_slli_si128(key, 4));
		}

		bool rijndael128_128_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			rk[0] = _mm_loadu_si128((const __m128i*) key);
			rk[1] = _mm_xor_si128(aes128_keyexpand(rk[0]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[0], 0x01), 0xff));
			rk[2] = _mm_xor_si128(aes128_keyexpand(rk[1]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[1], 0x02), 0xff));
			rk[3] = _mm_xor_si128(aes128_keyexpand(rk[2]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[2], 0x04), 0xff));
			rk[4] = _mm_xor_si128(aes128_keyexpand(rk[3]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[3], 0x08), 0xff));
			rk[5] = _mm_xor_si128(aes128_keyexpand(rk[4]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[4], 0x10), 0xff));
			rk[6] = _mm_xor_si128(aes128_keyexpand(rk[5]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[5], 0x20), 0xff));
			rk[7] = _mm_xor_si128(aes128_keyexpand(rk[6]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[6], 0x40), 0xff));
			rk[8] = _mm_xor_si128(aes128_keyexpand(rk[7]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[7], 0x80), 0xff));
			rk[9] = _mm_xor_si128(aes128_keyexpand(rk[8]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[8], 0x1B), 0xff));
			rk[10] = _mm_xor_si128(aes128_keyexpand(rk[9]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[9], 0x36), 0xff));

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[10]);
				std::swap(rk[1], rk[9]);
				std::swap(rk[2], rk[8]);
				std::swap(rk[3], rk[7]);
				std::swap(rk[4], rk[6]);

				rk[1] = _mm_aesimc_si128(rk[1]);
				rk[2] = _mm_aesimc_si128(rk[2]);
				rk[3] = _mm_aesimc_si128(rk[3]);
				rk[4] = _mm_aesimc_si128(rk[4]);
				rk[5] = _mm_aesimc_si128(rk[5]);
				rk[6] = _mm_aesimc_si128(rk[6]);
				rk[7] = _mm_aesimc_si128(rk[7]);
				rk[8] = _mm_aesimc_si128(rk[8]);
				rk[9] = _mm_aesimc_si128(rk[9]);
			}

			return true;
		}

		void rijndael128_128_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[1]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[2]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[3]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[4]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[5]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[6]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[7]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[8]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[9]);
			xmm15 = _mm_aesenclast_si128(xmm15, rk[10]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_128_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[1]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[2]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[3]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[4]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[5]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[6]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[7]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[8]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[9]);
			xmm15 = _mm_aesdeclast_si128(xmm15, rk[10]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

#define mm_shuffle_int32(t1, t2, a, r) \
	f1 = _mm_castsi128_pd(t1); \
	f2 = _mm_castsi128_pd(t2); \
	f3 = _mm_shuffle_pd(f1, f2, a); \
	r = _mm_castpd_si128(f3);

		void rijndael128_160_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[1]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[2]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[3]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[4]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[5]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[6]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[7]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[8]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[9]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[10]);
			xmm15 = _mm_aesenclast_si128(xmm15, rk[11]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_160_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[1]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[2]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[3]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[4]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[5]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[6]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[7]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[8]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[9]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[10]);
			xmm15 = _mm_aesdeclast_si128(xmm15, rk[11]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		static inline void KEY_192_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3)
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
			temp4 = _mm_slli_si128(*temp3, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			*temp3 = _mm_xor_si128(*temp3, *temp2);
		}

		bool rijndael128_192_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 192 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));
			__m128i temp2;
			rk[0] = temp1;
			rk[1] = temp3;
			__m128d  f1, f2, f3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[1], temp1, 0, rk[1]);
			mm_shuffle_int32(temp1, temp3, 1, rk[2]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[3] = temp1;
			rk[4] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[4], temp1, 0, rk[4]);
			mm_shuffle_int32(temp1, temp3, 1, rk[5]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[6] = temp1;
			rk[7] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[7], temp1, 0, rk[7]);
			mm_shuffle_int32(temp1, temp3, 1, rk[8]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[9] = temp1;
			rk[10] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[10], temp1, 0, rk[10]);
			mm_shuffle_int32(temp1, temp3, 1, rk[11]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[12] = temp1;

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[12]);
				std::swap(rk[1], rk[11]);
				std::swap(rk[2], rk[10]);
				std::swap(rk[3], rk[9]);
				std::swap(rk[4], rk[8]);
				std::swap(rk[5], rk[7]);

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
			}

			return true;
		}

		void rijndael128_192_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[1]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[2]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[3]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[4]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[5]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[6]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[7]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[8]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[9]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[10]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[11]);
			xmm15 = _mm_aesenclast_si128(xmm15, rk[12]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_192_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[1]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[2]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[3]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[4]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[5]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[6]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[7]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[8]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[9]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[10]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[11]);
			xmm15 = _mm_aesdeclast_si128(xmm15, rk[12]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		static inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2)
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
		static inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3)
		{
			__m128i temp2, temp4;
			temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
			temp2 = _mm_shuffle_epi32(temp4, 0xaa);
			temp4 = _mm_slli_si128(*temp3, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			temp4 = _mm_slli_si128(temp4, 0x4);
			*temp3 = _mm_xor_si128(*temp3, temp4);
			*temp3 = _mm_xor_si128(*temp3, temp2);
		}

		bool rijndael128_256_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			__m128i temp1 = _mm_loadu_si128((__m128i*) key);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (key + 16));
			__m128i temp2;
			rk[0] = temp1;
			rk[1] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[2] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[3] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[4] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[5] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[6] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[7] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[8] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[9] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[10] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[11] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[12] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[13] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[14] = temp1;

			if (direction == block_cipher::decryption)
			{
				std::swap(rk[0], rk[14]);
				std::swap(rk[1], rk[13]);
				std::swap(rk[2], rk[12]);
				std::swap(rk[3], rk[11]);
				std::swap(rk[4], rk[10]);
				std::swap(rk[5], rk[9]);
				std::swap(rk[6], rk[8]);

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
				rk[13] = _mm_aesimc_si128(rk[13]);
			}

			return true;
		}

		void rijndael128_256_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[1]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[2]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[3]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[4]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[5]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[6]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[7]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[8]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[9]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[10]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[11]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[12]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[13]);
			xmm15 = _mm_aesenclast_si128(xmm15, rk[14]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_256_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[1]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[2]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[3]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[4]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[5]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[6]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[7]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[8]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[9]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[10]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[11]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[12]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[13]);
			xmm15 = _mm_aesdeclast_si128(xmm15, rk[14]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_224_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[1]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[2]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[3]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[4]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[5]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[6]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[7]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[8]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[9]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[10]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[11]);
			xmm15 = _mm_aesenc_si128(xmm15, rk[12]);
			xmm15 = _mm_aesenclast_si128(xmm15, rk[13]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		void rijndael128_224_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i xmm15 = _mm_loadu_si128((const __m128i*) in);

			xmm15 = _mm_xor_si128(xmm15, rk[0]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[1]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[2]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[3]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[4]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[5]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[6]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[7]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[8]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[9]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[10]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[11]);
			xmm15 = _mm_aesdec_si128(xmm15, rk[12]);
			xmm15 = _mm_aesdeclast_si128(xmm15, rk[13]);
			_mm_storeu_si128((__m128i*) out, xmm15);
		}

		bool rijndael256_256_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			__m128i temp1 = _mm_loadu_si128((__m128i*) key);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (key + 16));
			__m128i temp2;
			rk[0] = temp1;
			rk[1] = temp3;

			// i=0
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[2] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[3] = temp3;

			// i=1
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[4] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[5] = temp3;

			// i=2
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[6] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[7] = temp3;

			// i=3
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[8] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[9] = temp3;

			//i=4
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[10] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[11] = temp3;

			//i=5
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[12] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[13] = temp3;

			//i=6
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[14] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[15] = temp3;

			//i=7
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[16] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[17] = temp3;

			//i=8
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[18] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[19] = temp3;

			//i=9
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[20] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[21] = temp3;

			//i=10
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x6c);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[22] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[23] = temp3;

			//i=11
			temp2 = _mm_aeskeygenassist_si128(temp3, 0xd8);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[24] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[25] = temp3;

			//i=12
			temp2 = _mm_aeskeygenassist_si128(temp3, 0xab);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[26] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[27] = temp3;

			//i=13
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4d);
			KEY_256_ASSIST_1(&temp1, &temp2);
			rk[28] = temp1;
			KEY_256_ASSIST_2(&temp1, &temp3);
			rk[29] = temp3;

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

		void rijndael256_256_impl_aesni::encryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i tmp1, tmp2, data1, data2;
			__m128i RIJNDAEL256_MASK = _mm_set_epi32(0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100);
			__m128i BLEND_MASK = _mm_set_epi32(0x80000000, 0x80800000, 0x80800000, 0x80808000);
			int j;

			data1 = _mm_loadu_si128(&((__m128i*)in)[0]);
			data2 = _mm_loadu_si128(&((__m128i*)in)[1]);
			data1 = _mm_xor_si128(data1, rk[0]);
			data2 = _mm_xor_si128(data2, rk[1]);
			for (j = 1; j < 14; j++) {
				tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
				tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
				tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
				tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
				data1 = _mm_aesenc_si128(tmp1, rk[j * 2]);
				data2 = _mm_aesenc_si128(tmp2, rk[j * 2 + 1]);
			}

			tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
			tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
			tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
			tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
			tmp1 = _mm_aesenclast_si128(tmp1, rk[j * 2 + 0]);
			tmp2 = _mm_aesenclast_si128(tmp2, rk[j * 2 + 1]);
			_mm_storeu_si128(&((__m128i*)out)[0], tmp1);
			_mm_storeu_si128(&((__m128i*)out)[1], tmp2);
		}

		void rijndael256_256_impl_aesni::decryptBlock(const uint8_t* in, uint8_t* out)
		{
			__m128i tmp1, tmp2, data1, data2;
			__m128i RIJNDAEL256_MASK_INV = _mm_set_epi32(0x0b0a0d0c, 0x07060908, 0x03020504, 0x0f0e0100);
			__m128i BLEND_MASK_INV = _mm_set_epi32(0x80808000, 0x80800000, 0x80800000, 0x80000000);
			int j;

			data1 = _mm_loadu_si128(&((__m128i*)in)[0]);
			data2 = _mm_loadu_si128(&((__m128i*)in)[1]);
			data1 = _mm_xor_si128(data1, rk[0]);
			data2 = _mm_xor_si128(data2, rk[1]);
			for (j = 1; j < 14; j++) {
				tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK_INV);
				tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK_INV);
				tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK_INV);
				tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK_INV);
				data1 = _mm_aesdec_si128(tmp1, rk[j * 2]);
				data2 = _mm_aesdec_si128(tmp2, rk[j * 2 + 1]);
			}

			tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK_INV);
			tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK_INV);
			tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK_INV);
			tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK_INV);
			tmp1 = _mm_aesdeclast_si128(tmp1, rk[j * 2 + 0]);
			tmp2 = _mm_aesdeclast_si128(tmp2, rk[j * 2 + 1]);
			_mm_storeu_si128(&((__m128i*)out)[0], tmp1);
			_mm_storeu_si128(&((__m128i*)out)[1], tmp2);
		}

		bool rijndael256_128_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			rk[0] = _mm_loadu_si128((const __m128i*) key);
			rk[1] = _mm_xor_si128(aes128_keyexpand(rk[0]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[0], 0x01), 0xff));
			rk[2] = _mm_xor_si128(aes128_keyexpand(rk[1]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[1], 0x02), 0xff));
			rk[3] = _mm_xor_si128(aes128_keyexpand(rk[2]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[2], 0x04), 0xff));
			rk[4] = _mm_xor_si128(aes128_keyexpand(rk[3]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[3], 0x08), 0xff));
			rk[5] = _mm_xor_si128(aes128_keyexpand(rk[4]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[4], 0x10), 0xff));
			rk[6] = _mm_xor_si128(aes128_keyexpand(rk[5]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[5], 0x20), 0xff));
			rk[7] = _mm_xor_si128(aes128_keyexpand(rk[6]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[6], 0x40), 0xff));
			rk[8] = _mm_xor_si128(aes128_keyexpand(rk[7]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[7], 0x80), 0xff));
			rk[9] = _mm_xor_si128(aes128_keyexpand(rk[8]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[8], 0x1B), 0xff));
			rk[10] = _mm_xor_si128(aes128_keyexpand(rk[9]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[9], 0x36), 0xff));
			rk[11] = _mm_xor_si128(aes128_keyexpand(rk[10]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[10], 0x6c), 0xff));
			rk[12] = _mm_xor_si128(aes128_keyexpand(rk[11]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[11], 0xd8), 0xff));
			rk[13] = _mm_xor_si128(aes128_keyexpand(rk[12]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[12], 0xab), 0xff));
			rk[14] = _mm_xor_si128(aes128_keyexpand(rk[13]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[13], 0x4d), 0xff));
			rk[15] = _mm_xor_si128(aes128_keyexpand(rk[14]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[14], 0x9a), 0xff));
			rk[16] = _mm_xor_si128(aes128_keyexpand(rk[15]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[15], 0x2f), 0xff));
			rk[17] = _mm_xor_si128(aes128_keyexpand(rk[16]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[16], 0x5e), 0xff));
			rk[18] = _mm_xor_si128(aes128_keyexpand(rk[17]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[17], 0xbc), 0xff));
			rk[19] = _mm_xor_si128(aes128_keyexpand(rk[18]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[18], 0x63), 0xff));
			rk[20] = _mm_xor_si128(aes128_keyexpand(rk[19]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[19], 0xc6), 0xff));
			rk[21] = _mm_xor_si128(aes128_keyexpand(rk[20]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[20], 0x97), 0xff));
			rk[22] = _mm_xor_si128(aes128_keyexpand(rk[21]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[21], 0x35), 0xff));
			rk[23] = _mm_xor_si128(aes128_keyexpand(rk[22]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[22], 0x6a), 0xff));
			rk[24] = _mm_xor_si128(aes128_keyexpand(rk[23]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[23], 0xd4), 0xff));
			rk[25] = _mm_xor_si128(aes128_keyexpand(rk[24]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[24], 0xb3), 0xff));
			rk[26] = _mm_xor_si128(aes128_keyexpand(rk[25]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[25], 0x7d), 0xff));
			rk[27] = _mm_xor_si128(aes128_keyexpand(rk[26]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[26], 0xfa), 0xff));
			rk[28] = _mm_xor_si128(aes128_keyexpand(rk[27]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[27], 0xef), 0xff));
			rk[29] = _mm_xor_si128(aes128_keyexpand(rk[28]), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(rk[28], 0xc5), 0xff));

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

		bool rijndael256_192_impl_aesni::init(const uint8_t* key, block_cipher::direction direction)
		{
			uint8_t keycopy[32];
			memset(keycopy, 0, sizeof(keycopy));
			memcpy(keycopy, key, 192 / 8);

			__m128i temp1 = _mm_loadu_si128((__m128i*) keycopy);
			__m128i temp3 = _mm_loadu_si128((__m128i*) (keycopy + 16));
			__m128i temp2;
			rk[0] = temp1;
			rk[1] = temp3;
			__m128d  f1, f2, f3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[1], temp1, 0, rk[1]);
			mm_shuffle_int32(temp1, temp3, 1, rk[2]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[3] = temp1;
			rk[4] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[4], temp1, 0, rk[4]);
			mm_shuffle_int32(temp1, temp3, 1, rk[5]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[6] = temp1;
			rk[7] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[7], temp1, 0, rk[7]);
			mm_shuffle_int32(temp1, temp3, 1, rk[8]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[9] = temp1;
			rk[10] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[10], temp1, 0, rk[10]);
			mm_shuffle_int32(temp1, temp3, 1, rk[11]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[12] = temp1;
			rk[13] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[13], temp1, 0, rk[13]);
			mm_shuffle_int32(temp1, temp3, 1, rk[14]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[15] = temp1;
			rk[16] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x6c);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[16], temp1, 0, rk[16]);
			mm_shuffle_int32(temp1, temp3, 1, rk[17]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xd8);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[18] = temp1;
			rk[19] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xab);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[19], temp1, 0, rk[19]);
			mm_shuffle_int32(temp1, temp3, 1, rk[20]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x4d);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[21] = temp1;
			rk[22] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x9a);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[22], temp1, 0, rk[22]);
			mm_shuffle_int32(temp1, temp3, 1, rk[23]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x2f);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[24] = temp1;
			rk[25] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x5e);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[25], temp1, 0, rk[25]);
			mm_shuffle_int32(temp1, temp3, 1, rk[26]);

			temp2 = _mm_aeskeygenassist_si128(temp3, 0xbc);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			rk[27] = temp1;
			rk[28] = temp3;

			temp2 = _mm_aeskeygenassist_si128(temp3, 0x63);
			KEY_192_ASSIST(&temp1, &temp2, &temp3);
			mm_shuffle_int32(rk[28], temp1, 0, rk[28]);
			mm_shuffle_int32(temp1, temp3, 1, rk[29]);

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
