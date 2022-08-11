/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "ctr.h"
#include "cpuinfo.h"
#include <assert.h>
#include <memory.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include "portability.h"

namespace cppcrypto
{

	static inline void xor_block_256(const unsigned char* in, const unsigned char* prev, unsigned char* out)
	{
		//#define USE_AVX
#ifdef USE_AVX
		if (cpu_info::avx())
		{
			__m256i b1 = _mm256_loadu_si256((const __m256i*) in);
			__m256i p1 = _mm256_loadu_si256((const __m256i*) prev);

			_mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(b1, p1));
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
			}
			else {
				for (int i = 0; i < 32; i++)
					out[i] = in[i] ^ prev[i];
			}

	}

	static inline void xor_block_128(const unsigned char* in, const unsigned char* prev, unsigned char* out)
	{
		if (cpu_info::sse2())
		{
			__m128i b = _mm_loadu_si128((const __m128i*) in);
			__m128i p = _mm_loadu_si128((const __m128i*) prev);

			_mm_storeu_si128((__m128i*) out, _mm_xor_si128(b, p));
		}
		else {
			for (int i = 0; i < 16; i++)
				out[i] = in[i] ^ prev[i];
		}

	}

	static inline void xor_block_128n(const unsigned char* in, const unsigned char* prev, unsigned char* out, size_t n)
	{
		if (cpu_info::sse2())
		{
			__m128i b = _mm_loadu_si128((const __m128i*) in);
			__m128i p = _mm_loadu_si128((const __m128i*) prev);

			_mm_storeu_si128((__m128i*) out, _mm_xor_si128(b, p));
			for (size_t i = 16; i < n; i++)
				out[i] = in[i] ^ prev[i];
		}
		else {
			for (size_t i = 0; i < n; i++)
				out[i] = in[i] ^ prev[i];
		}

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
				for (int i = 0; i < 64; i++)
					out[i] = in[i] ^ prev[i];
			}

	}

	ctr::ctr(const block_cipher& cipher)
		: block_(0), iv_(0), pos(0), nb_(cipher.blocksize() / 8), cipher_(cipher.clone())
	{
		block_ = new unsigned char[nb_];
		iv_ = new unsigned char[nb_];
	}

	ctr::~ctr()
	{
		clear();
		delete[] block_;
		delete[] iv_;
	}

	void ctr::clear()
	{
		zero_memory(block_, nb_);
		zero_memory(iv_, nb_);
		cipher_->clear();
	}

	void ctr::init(const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen)
	{
		assert(keylen == cipher_->keysize() / 8);
		assert(ivlen <= nb_);
		cipher_->init(key, block_cipher::encryption); // always encryption in CTR
		memcpy(iv_, iv, ivlen);
		memset(iv_ + ivlen, 0, nb_ - ivlen);
		pos = 0;
	}

	static inline void incrementCounter(unsigned char* ctr, size_t nb, unsigned char* block, block_cipher* cipher)
	{
		cipher->encrypt_block(ctr, block);
		bool carry = true;
		for (size_t i = nb - 1; i < nb && carry; i--)
			carry = !++ctr[i];
	}

	void ctr::encrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		size_t i = 0;
		size_t nb = nb_;
		if (pos)
		{
			while (pos < len && pos < nb)
			{
				out[i] = in[i] ^ block_[pos++];
				++i;
			}
			len -= i;
		}
		if (len)
			pos = 0;
		for (; len; len -= std::min(nb, len))
		{
			incrementCounter(iv_, nb, block_, cipher_.get());
			if (len >= nb)
			{
				if (nb == 128 / 8)
				{
					xor_block_128(in + i, block_, out + i);
					i += nb;
				}
				else if (nb == 256 / 8)
				{
					xor_block_256(in + i, block_, out + i);
					i += nb;
				}
				else if (nb == 512 / 8)
				{
					xor_block_512(in + i, block_, out + i);
					i += nb;
				}
				else if (nb > 128 / 8 && nb < 256 / 8)
				{
					xor_block_128n(in + i, block_, out + i, nb);
					i += nb;
				}
				else
					for (unsigned int j = 0; j < nb; j++, i++)
						out[i] = in[i] ^ block_[j];
			}
			else
				for (; pos < len; pos++)
					out[i] = in[i] ^ block_[pos];
		}
	}

	void ctr::decrypt(const unsigned char* in, size_t len, unsigned char* out)
	{
		encrypt(in, len, out);
	}

}
