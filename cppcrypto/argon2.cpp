/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

//#define CPPCRYPTO_DEBUG

#include "argon2.h"
#include "portability.h"
#include "cpuinfo.h"
#include "alignedarray.h"
#include <algorithm>
#include <memory.h>
#include "blake2.h"
#include "thread_pool.h"
#include <emmintrin.h>

#ifdef _MSC_VER
#define inline __forceinline
#endif

namespace cppcrypto
{
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
				for (int i = 0; i < 64 / 8; i++)
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

	static inline void HP(unsigned char* in, uint32_t inlen, unsigned char* out, uint32_t outlen)
	{
		unsigned char buf1[64], buf2[64];
		blake2b hasher(std::min(outlen, 64U)*8);
		hasher.init();
		hasher.update(reinterpret_cast<unsigned char*>(&outlen), sizeof(outlen));
		hasher.update(in, inlen);

		if (outlen <= 64)
			return hasher.final(out);

		hasher.final(buf1);
		uint32_t rem = outlen % 64;
		if (!rem)
			rem = 64;
		uint32_t vnum = (outlen - rem) / 32;
		unsigned char* inb = buf1;
		unsigned char* outb = buf2;
		memcpy(out, buf1, 32);
		out += 32;
		for (uint32_t i = 1; i < vnum; i++)
		{
			hasher.hash_string(inb, 64, outb);
			memcpy(out, outb, 32);
			out += 32;
			std::swap(inb, outb);
		}
		blake2b(rem*8).hash_string(inb, 64, out);
	}

	static inline void fill_first_blocks(unsigned char* B, uint32_t p, uint32_t q, unsigned char* h0)
	{
		unsigned char buf[64 + 8];
		memcpy(buf, h0, 64);
		for (uint32_t i = 0; i < p; i++)
		{
			memcpy(buf + 68, &i, 4);
			memset(buf + 64, 0, 4);
			HP(buf, 72, B + i*q * 1024, 1024);
			buf[64] = 1;
			HP(buf, 72, B + i*q * 1024 + 1024, 1024);
#ifdef CPPCRYPTO_DEBUG
			printf("block[%d]: ", i*q);
			for (int k = 0; k < 1024; k++)
				printf("%02x", B[i*q * 1024 + k]);
			printf("\n");
			printf("block[%d]: ", i*q+1);
			for (int k = 0; k < 1024; k++)
				printf("%02x", B[i*q * 1024 + 1024 + k]);
			printf("\n");
#endif
		}
	}

	static inline void GP(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d)
	{
		a = a + b + 2 * uint64_t(uint32_t(a)) * uint64_t(uint32_t(b));
		d = rotater64(d ^ a, 32);
		c = c + d + 2 * uint64_t(uint32_t(c)) * uint64_t(uint32_t(d));
		b = rotater64(b ^ c, 24);
		a = a + b + 2 * uint64_t(uint32_t(a)) * uint64_t(uint32_t(b));
		d = rotater64(d ^ a, 16);
		c = c + d + 2 * uint64_t(uint32_t(c)) * uint64_t(uint32_t(d));
		b = rotater64(b ^ c, 63);
	}

	static inline void P(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3, uint64_t& v4, uint64_t& v5, uint64_t& v6, uint64_t& v7,
		uint64_t& v8, uint64_t& v9, uint64_t& v10, uint64_t& v11, uint64_t& v12, uint64_t& v13, uint64_t& v14, uint64_t& v15)
	{
		GP(v0, v4, v8, v12);
		GP(v1, v5, v9, v13);
		GP(v2, v6, v10, v14);
		GP(v3, v7, v11, v15);
		GP(v0, v5, v10, v15);
		GP(v1, v6, v11, v12);
		GP(v2, v7, v8, v13);
		GP(v3, v4, v9, v14);
	}

	static inline void G(const unsigned char* in1, const unsigned char* in2, unsigned char* out, bool xor_output)
	{
		uint64_t r[128], rsave[128];
		xor_block_512r(in1, in2, (unsigned char*)r, 16);
		memcpy(rsave, r, 1024);

		P(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
		P(r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23], r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31]);
		P(r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39], r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47]);
		P(r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55], r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63]);
		P(r[64], r[65], r[66], r[67], r[68], r[69], r[70], r[71], r[72], r[73], r[74], r[75], r[76], r[77], r[78], r[79]);
		P(r[80], r[81], r[82], r[83], r[84], r[85], r[86], r[87], r[88], r[89], r[90], r[91], r[92], r[93], r[94], r[95]);
		P(r[96], r[97], r[98], r[99], r[100], r[101], r[102], r[103], r[104], r[105], r[106], r[107], r[108], r[109], r[110], r[111]);
		P(r[112], r[113], r[114], r[115], r[116], r[117], r[118], r[119], r[120], r[121], r[122], r[123], r[124], r[125], r[126], r[127]);

		P(r[0], r[1], r[16], r[17], r[32], r[33], r[48], r[49], r[64], r[65], r[80], r[81], r[96], r[97], r[112], r[113]);
		P(r[2], r[3], r[18], r[19], r[34], r[35], r[50], r[51], r[66], r[67], r[82], r[83], r[98], r[99], r[114], r[115]);
		P(r[4], r[5], r[20], r[21], r[36], r[37], r[52], r[53], r[68], r[69], r[84], r[85], r[100], r[101], r[116], r[117]);
		P(r[6], r[7], r[22], r[23], r[38], r[39], r[54], r[55], r[70], r[71], r[86], r[87], r[102], r[103], r[118], r[119]);
		P(r[8], r[9], r[24], r[25], r[40], r[41], r[56], r[57], r[72], r[73], r[88], r[89], r[104], r[105], r[120], r[121]);
		P(r[10], r[11], r[26], r[27], r[42], r[43], r[58], r[59], r[74], r[75], r[90], r[91], r[106], r[107], r[122], r[123]);
		P(r[12], r[13], r[28], r[29], r[44], r[45], r[60], r[61], r[76], r[77], r[92], r[93], r[108], r[109], r[124], r[125]);
		P(r[14], r[15], r[30], r[31], r[46], r[47], r[62], r[63], r[78], r[79], r[94], r[95], r[110], r[111], r[126], r[127]);
		if (!xor_output)
			xor_block_512r((const unsigned char*)r, (const unsigned char*)rsave, out, 16);
		else
		{
			xor_block_512r((const unsigned char*)r, (const unsigned char*)rsave, (unsigned char*)r, 16);
			xor_block_512r((const unsigned char*)r, out, out, 16);
		}
	}

	static inline void calc_indices(uint64_t r, uint64_t l, uint64_t s, uint64_t m, uint64_t t, uint64_t x, uint64_t i, unsigned char* indices)
	{
		unsigned char buf1[1024], buf2[1024];
		memset(buf1, 0, 1024);
		memset(buf2+56, 0, 968);
		memcpy(buf2, &r, 8);
		memcpy(buf2+8, &l, 8);
		memcpy(buf2+16, &s, 8);
		memcpy(buf2+24, &m, 8);
		memcpy(buf2+32, &t, 8);
		memcpy(buf2+40, &x, 8);
		memcpy(buf2+48, &i, 8);
#ifdef CPPCRYPTO_DEBUG
		printf("feeding to double-G: ");
			for (int i = 0; i < 1024; i++)
				printf("%02x", buf2[i]);
		printf("\n");
#endif

		G(buf1, buf2, indices, false);
		G(buf1, indices, indices, false);

#ifdef CPPCRYPTO_DEBUG
		printf("result of double-G: ");
		for (int i = 0; i < 1024; i++)
			printf("%02x", indices[i]);
		printf("\n");
#endif
	}

	static inline void calc_lanes(uint32_t iteration, uint32_t slice, unsigned char* B, uint32_t p, uint32_t q, uint32_t s, detail::thread_pool& tp, uint32_t y, uint32_t tt, uint32_t mt, argon2_version version)
	{
		uint32_t firstcol = slice * s;
		uint32_t startcol = firstcol + (iteration || slice ? 0 : 2);
		bool xor_output = iteration && version != argon2_version::version12;

#ifdef NO_CPP11_THREADS
#pragma omp parallel for
#endif
		for (uint32_t lane = 0; lane < p; lane++)
		{
#ifndef NO_CPP11_THREADS
			tp.run_async([=] {
#endif
				unsigned char indices[1024];
				uint64_t counter = 1;
				unsigned char* current = indices + 1024 - 8;
				for (uint32_t column = startcol; column < firstcol + s; column++)
				{
					unsigned char* thisB = B + (lane*q + column) * 1024;
					unsigned char* prevB = column ? thisB - 1024 : B + (lane*q + q - 1) * 1024;
					uint32_t J1, J2;
					if (!y || (y == 2 && (iteration || slice >= 2)))
					{
						J1 = *(uint32_t*)prevB;
						J2 = *(((uint32_t*)prevB) + 1);
					}
					else
					{
						current += 8;
						if (current == indices + 1024)
						{
							calc_indices(iteration, lane, slice, mt, tt, y, counter++, indices);
							current = indices;
							if (!iteration && !slice && counter == 2) // skip 1st two numbers
								current += 16;
						}
						J1 = *(uint32_t*)current;
						J2 = *(((uint32_t*)current) + 1);
					}
#ifdef CPPCRYPTO_DEBUG
					uint32_t origJ1 = J1;
#endif
					uint32_t l = !slice && !iteration ? lane : J2 % p;
					uint32_t R = (iteration ? 3 : slice) * s;
					if (l == lane)
						R += (column - firstcol - 1);
					else if (column == startcol)
						--R;

					J1 = (static_cast<uint64_t>(J1)*static_cast<uint64_t>(J1)) >> 32;
					J1 = (static_cast<uint64_t>(R)*static_cast<uint64_t>(J1)) >> 32;
					J1 = R - 1 - J1;
					unsigned char* otherB = B + l * q * 1024;
					if (iteration)
						otherB += (slice + 1) * s * 1024;
					otherB += J1 * 1024;
					if (otherB >= B + (l + 1) * q * 1024)
						otherB -= q * 1024;
#ifdef CPPCRYPTO_DEBUG
					printf("i=%d,s=%d,l=%d,c=%d: i=%d,j=%d (J1=%d,J2=%d R=%d)\n", iteration, slice, lane, (column-slice*s), l, (otherB - (B + (l*q * 1024)))/1024, origJ1, J2, R);
#endif
					G(prevB, otherB, thisB, xor_output);
				}
#ifndef NO_CPP11_THREADS
			});
#endif
		}
		tp.wait_for_all();
	}

	static inline void argon2(const char* password, uint32_t pwd_len, const unsigned char* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, unsigned char* dk, uint32_t dklen, uint32_t y,
		unsigned char* data, uint32_t datalen, unsigned char* secret, uint32_t secretlen, argon2_version version)
	{
		unsigned char h0[64];
		blake2b ih(512);
		ih.init();
		uint32_t v = static_cast<uint32_t>(version);
		ih.update(reinterpret_cast<const unsigned char*>(&p), sizeof(p));
		ih.update(reinterpret_cast<const unsigned char*>(&dklen), sizeof(dklen));
		ih.update(reinterpret_cast<const unsigned char*>(&m), sizeof(m));
		ih.update(reinterpret_cast<const unsigned char*>(&t), sizeof(t));
		ih.update(reinterpret_cast<const unsigned char*>(&v), sizeof(v));
		ih.update(reinterpret_cast<const unsigned char*>(&y), sizeof(y));
		ih.update(reinterpret_cast<const unsigned char*>(&pwd_len), sizeof(pwd_len));
		ih.update(reinterpret_cast<const unsigned char*>(password), pwd_len);
		ih.update(reinterpret_cast<const unsigned char*>(&salt_len), sizeof(salt_len));
		ih.update(salt, salt_len);
		ih.update(reinterpret_cast<const unsigned char*>(&secretlen), sizeof(secretlen));
		ih.update(secret, secretlen);
		ih.update(reinterpret_cast<const unsigned char*>(&datalen), sizeof(datalen));
		ih.update(data, datalen);
		ih.final(h0);
#ifdef CPPCRYPTO_DEBUG
		printf("initial hash: ");
		for (int i = 0; i < 64; i++)
			printf("%02x", h0[i]);
		printf("\n");
#endif

		uint32_t msize = std::max((m / 4 / p) * 4 * p, 8*p);
		uint32_t q = msize / p;
		uint32_t s = q / 4;
		unsigned char* B = new unsigned char[msize * 1024];
		fill_first_blocks(B, p, q, h0);
		detail::thread_pool tp(p);
		for (uint32_t iteration = 0; iteration < t; iteration++)
		{
			for (uint32_t slice = 0; slice < 4; slice++)
			{
				calc_lanes(iteration, slice, B, p, q, s, tp, y, t, msize, version);
			}
#ifdef CPPCRYPTO_DEBUG
			printf("after iteration %d:\n", iteration);
			for (uint32_t i = 0; i < p; i++)
			{
				printf("block[%d]: ", i*q);
				for (int k = 0; k < 1024; k++)
					printf("%02x", B[i*q * 1024 + k]);
				printf("\n");
				printf("block[%d]: ", i*q+1);
				for (int k = 0; k < 1024; k++)
					printf("%02x", B[i*q * 1024 + 1024 + k]);
				printf("\n");
			}
#endif
		}
		unsigned char bm[1024];
		memset(bm, 0, sizeof(bm));
		for (uint32_t i = 0; i < p; i++)
		{
#ifdef CPPCRYPTO_DEBUG
			printf("blast[%d]: ", i);
			for (int k = 0; k < 1024; k++)
				printf("%02x", (B + ((i + 1)*q - 1) * 1024)[k]);
			printf("\n");
#endif
			xor_block_512r(bm, B + ((i + 1)*q - 1) * 1024, bm, 16);
		}

#ifdef CPPCRYPTO_DEBUG
		printf("bm: ");
		for (int k = 0; k < 1024; k++)
			printf("%02x", bm[k]);
		printf("\n");
#endif
		HP(bm, 1024, dk, dklen);
		zero_memory(B, msize * 1024);
		zero_memory(h0, 64);
		zero_memory(bm, 1024);
		delete[] B;
	}

	void argon2d(const char* password, uint32_t pwd_len, const unsigned char* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, unsigned char* dk, uint32_t dklen,
		unsigned char* data, uint32_t datalen, unsigned char* secret, uint32_t secretlen, argon2_version version)
	{
		return argon2(password, pwd_len, salt, salt_len, p, m, t, dk, dklen, 0, data, datalen, secret, secretlen, version);
	}

	void argon2i(const char* password, uint32_t pwd_len, const unsigned char* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, unsigned char* dk, uint32_t dklen,
		unsigned char* data, uint32_t datalen, unsigned char* secret, uint32_t secretlen, argon2_version version)
	{
		return argon2(password, pwd_len, salt, salt_len, p, m, t, dk, dklen, 1, data, datalen, secret, secretlen, version);
	}

	void argon2id(const char* password, uint32_t pwd_len, const unsigned char* salt, uint32_t salt_len, uint32_t p, uint32_t m, uint32_t t, unsigned char* dk, uint32_t dklen,
		unsigned char* data, uint32_t datalen, unsigned char* secret, uint32_t secretlen, argon2_version version)
	{
		return argon2(password, pwd_len, salt, salt_len, p, m, t, dk, dklen, 2, data, datalen, secret, secretlen, version);
	}

}

