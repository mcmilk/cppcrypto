/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include <emmintrin.h>
#include "scrypt.h"
#include "portability.h"
#include "cpuinfo.h"
#include "alignedarray.h"
#include <algorithm>
#include <memory.h>
#include "sha256.h"
#include "thread_pool.h"

extern "C"
{
	void crypto_scrypt_smix_sse2(unsigned char *, size_t, uint64_t, void *, void *);
}

namespace cppcrypto
{

	static inline void salsa20_8_core(const uint32_t* in, uint32_t* out)
	{
		uint32_t x[16];
		memcpy(x, in, 64);
		for (int i = 0; i < 4; i++)
		{
			x[4] ^= rotatel32(x[0] + x[12], 7);
			x[8] ^= rotatel32(x[4] + x[0], 9);
			x[12] ^= rotatel32(x[8] + x[4], 13);
			x[0] ^= rotatel32(x[12] + x[8], 18);
			x[9] ^= rotatel32(x[5] + x[1], 7);
			x[13] ^= rotatel32(x[9] + x[5], 9);
			x[1] ^= rotatel32(x[13] + x[9], 13);
			x[5] ^= rotatel32(x[1] + x[13], 18);
			x[14] ^= rotatel32(x[10] + x[6], 7);
			x[2] ^= rotatel32(x[14] + x[10], 9);
			x[6] ^= rotatel32(x[2] + x[14], 13);
			x[10] ^= rotatel32(x[6] + x[2], 18);
			x[3] ^= rotatel32(x[15] + x[11], 7);
			x[7] ^= rotatel32(x[3] + x[15], 9);
			x[11] ^= rotatel32(x[7] + x[3], 13);
			x[15] ^= rotatel32(x[11] + x[7], 18);
			x[1] ^= rotatel32(x[0] + x[3], 7);
			x[2] ^= rotatel32(x[1] + x[0], 9);
			x[3] ^= rotatel32(x[2] + x[1], 13);
			x[0] ^= rotatel32(x[3] + x[2], 18);
			x[6] ^= rotatel32(x[5] + x[4], 7);
			x[7] ^= rotatel32(x[6] + x[5], 9);
			x[4] ^= rotatel32(x[7] + x[6], 13);
			x[5] ^= rotatel32(x[4] + x[7], 18);
			x[11] ^= rotatel32(x[10] + x[9], 7);
			x[8] ^= rotatel32(x[11] + x[10], 9);
			x[9] ^= rotatel32(x[8] + x[11], 13);
			x[10] ^= rotatel32(x[9] + x[8], 18);
			x[12] ^= rotatel32(x[15] + x[14], 7);
			x[13] ^= rotatel32(x[12] + x[15], 9);
			x[14] ^= rotatel32(x[13] + x[12], 13);
			x[15] ^= rotatel32(x[14] + x[13], 18);
		}
		for (int i = 0; i < 16; ++i)
			out[i] = x[i] + in[i];
	}

	static inline void xor_block_512(const unsigned char* in, const unsigned char* prev, unsigned char* out)
	{
#ifdef USE_AVX
		if (cpu_info::avx())
		{
			__m256i b1 = _mm256_loadu_si256((const __m256i*) in);
			__m256i p1 = _mm256_loadu_si256((const __m256i*) prev);
			__m256i b2 = _mm256_loadu_si256((const __m256i*) (in + 32));
			__m256i p2 = _mm256_loadu_si256((const __m256i*) (prev + 32));

			_mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(b1, p1));
			_mm256_storeu_si256((__m256i*) (out + 32), _mm256_xor_si256(b2, p2));
			_mm256_zeroupper();
		}
		else
#endif
			if (cpu_info::sse2())
			{
				__m128i b1 = _mm_loadu_si128((const __m128i*) in);
				__m128i p1 = _mm_loadu_si128((const __m128i*) prev);
				__m128i b2 = _mm_loadu_si128((const __m128i*) (in + 16));
				__m128i p2 = _mm_loadu_si128((const __m128i*) (prev + 16));

				_mm_storeu_si128((__m128i*) out, _mm_xor_si128(b1, p1));
				_mm_storeu_si128((__m128i*) (out + 16), _mm_xor_si128(b2, p2));

				b1 = _mm_loadu_si128((const __m128i*) (in + 32));
				p1 = _mm_loadu_si128((const __m128i*) (prev + 32));
				b2 = _mm_loadu_si128((const __m128i*) (in + 48));
				p2 = _mm_loadu_si128((const __m128i*) (prev + 48));

				_mm_storeu_si128((__m128i*) (out + 32), _mm_xor_si128(b1, p1));
				_mm_storeu_si128((__m128i*) (out + 48), _mm_xor_si128(b2, p2));

			}
			else {
				for (int i = 0; i < 64/8; i++)
					((uint64_t*)out)[i] = ((uint64_t*)in)[i] ^ ((uint64_t*)prev)[i];
			}

	}

	static inline void xor_block_512r(const unsigned char* in, const unsigned char* prev, unsigned char* out, size_t r)
	{
		for (size_t i = 0; i < r; i++)
		{
			xor_block_512(in, prev, out);
			in += 64;
			out += 64;
			prev += 64;
		}
	}

	static inline void blockmix(uint32_t* B, size_t r, uint32_t* Y)
	{
		uint32_t X[16];
		size_t last = 2 * r - 1;
		memcpy(X, B + last*16, 64);
		for (size_t i = 0; i <= last; i+=2)
		{
			xor_block_512((unsigned char*)X, (unsigned char*)(&B[i * 16]), (unsigned char*)X);
			salsa20_8_core(X, X);
			memcpy(Y + i * 16/2, X, 64);
			xor_block_512((unsigned char*)X, (unsigned char*)(&B[(i+1) * 16]), (unsigned char*)X);
			salsa20_8_core(X, X);
			memcpy(Y + r * 16 + i * 16 / 2, X, 64);
		}
	}

	static inline uint64_t integerify(const uint32_t* B, size_t r)
	{
		size_t offset = (2 * r - 1) * 8;
		return ((const uint64_t*)B)[offset];
	}

	static inline void smix(unsigned char* B, size_t r, size_t N)
	{
		size_t bsbytes = 128 * r;
		size_t bs = bsbytes / 4;
		uint32_t* X = (uint32_t*)aligned_allocate(sizeof(uint32_t) * bs * (N + 2) + 64, 64);
		uint32_t* Y = X + bs;
		uint32_t* V = Y + bs;

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			crypto_scrypt_smix_sse2(B, r, N, V+16, X);
		else
#endif
		{
			memcpy(X, B, bsbytes);
			for (size_t i = 0; i < N; i++)
			{
				memcpy(V + i * bs, X, bsbytes);
				blockmix(X, r, Y);
				std::swap(X, Y);
			}
			for (size_t i = 0; i < N; i++)
			{
				size_t j = integerify(X, r) % N;
				xor_block_512r((unsigned char*)X, (unsigned char*)&V[j*bs], (unsigned char*)X, bsbytes / 64);
				blockmix(X, r, Y);
				std::swap(X, Y);
			}
			memcpy(B, X, bsbytes);
		}
		aligned_deallocate(X);
	}

	void scrypt(hmac& hmac, const unsigned char* salt, size_t salt_len, size_t N, size_t r, size_t p, unsigned char* dk, size_t dklen)
	{
		unsigned char* B = new unsigned char[p * 128 * r];
		pbkdf2(hmac, salt, salt_len, 1, B, p * 128 * r);

#ifdef NO_CPP11_THREADS
#pragma omp parallel for
		for (int i = 0; i < p; i++)
			smix(B + i * 128 * r, r, N);
#else
		detail::thread_pool tp(p);

		for (size_t i = 0; i < p; i++)
			tp.run_async([=] { smix(B + i * 128 * r, r, N); });

		tp.wait_for_all();
#endif
		pbkdf2(hmac, B, p * 128 * r, 1, dk, dklen);

		delete[] B;
	}

#if 0
	static inline void hex2array(const std::string& hex, unsigned char* array)
	{
		const char* pos = hex.c_str();
		for (size_t count = 0; count < hex.size() / 2; count++) {
			sscanf_s(pos, "%2hhx", array + count);
			pos += 2;
		}
	}

	void scrypttest()
	{
		unsigned char in1[512], in2[512], res[512];
		hex2array("7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e", in1);
		hex2array("a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81", in2);
		salsa20_8_core((uint32_t*)in1, (uint32_t*)res);
		printf("salsa - ");
		for (int i = 0; i < 64; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 64) ? " - MISMATCH" : " - MATCH");
		printf("\n");

		hex2array("f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89", in1);
		hex2array("a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f8120edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b77d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425", in2);
		blockmix((uint32_t*)in1, 1, (uint32_t*)res);
		printf("blockmix - ");
		for (int i = 0; i < 128; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 128) ? " - MISMATCH" : " - MATCH");
		printf("\n");
		hex2array("f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89", in1);
		hex2array("79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e", in2);
		smix(in1,1,16);
		printf("smix - ");
		for (int i = 0; i < 128; i++)
			printf("%02x", in1[i]);
		printf(memcmp(in2, in1, 128) ? " - MISMATCH" : " - MATCH");
		printf("\n");

		hex2array("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906", in2);
		scrypt(hmac(sha256(), ""), (const unsigned char*)"", 0, 16, 1, 1, res, 64);
		printf("scrypt(1) - ");
		for (int i = 0; i < 64; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 64) ? " - MISMATCH" : " - MATCH");
		printf("\n");

		hex2array("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", in2);
		scrypt(hmac(sha256(), "password"), (const unsigned char*)"NaCl", 4, 1024, 8, 16, res, 64);
		printf("scrypt(2) - ");
		for (int i = 0; i < 64; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 64) ? " - MISMATCH" : " - MATCH");
		printf("\n");

		hex2array("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887", in2);
		scrypt(hmac(sha256(), "pleaseletmein"), (const unsigned char*)"SodiumChloride", 14, 16384, 8, 1, res, 64);
		printf("scrypt(3) - ");
		for (int i = 0; i < 64; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 64) ? " - MISMATCH" : " - MATCH");
		printf("\n");

		hex2array("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4", in2);
		scrypt(hmac(sha256(), "pleaseletmein"), (const unsigned char*)"SodiumChloride", 14, 1048576, 8, 1, res, 64);
		printf("scrypt(4) - ");
		for (int i = 0; i < 64; i++)
			printf("%02x", res[i]);
		printf(memcmp(in2, res, 64) ? " - MISMATCH" : " - MATCH");
		printf("\n");
	}
#endif
}
