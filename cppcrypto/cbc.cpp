#include "cbc.h"
#include "cpuinfo.h"
#include <assert.h>
#include <memory.h>
#include <xmmintrin.h>

namespace cppcrypto
{

cbc::cbc()
	: block_(0), iv_(0), pos(0), nb_(0)
{
}

cbc::~cbc()
{
	delete[] block_;
	delete[] iv_;
}

void cbc::setCipher(const block_cipher& cipher)
{
	cipher_.reset(cipher.clone());
	delete[] block_;
	delete[] iv_;
	nb_ = cipher_->blockSize() / 8;
	block_ = new uint8_t[nb_];
	iv_ = new uint8_t[nb_];
}

void cbc::encryptInit(const uint8_t* key, const uint8_t* iv)
{
	cipher_->init(key, block_cipher::encryption);
	memcpy(iv_, iv, nb_);
	pos = 0;
}

void cbc::decryptInit(const uint8_t* key, const uint8_t* iv)
{
	cipher_->init(key, block_cipher::decryption);
	memcpy(iv_, iv, nb_);
	pos = 0;
}

static inline void xor_block_256(const uint8_t* in, const uint8_t* prev, uint8_t* out)
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

static inline void xor_block_128(const uint8_t* in, const uint8_t* prev, uint8_t* out)
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

void cbc::encryptUpdate(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen)
{
	resultlen = 0;
	unsigned int nb = nb_;
	if (pos && pos + len >= nb)
	{
		memcpy(block_ + pos, in, nb - pos);
		for (unsigned int i = 0; i < nb; i++)
			block_[i] ^= iv_[i];
		cipher_->encryptBlock(block_, out);
		memcpy(iv_, out, nb);
		in += nb - pos;
		len -= nb - pos;
		out += nb;
		resultlen += nb;
		pos = 0;
	}
	if (len >= nb)
	{
		if (nb == 16) // optimization for the most common block sizes
		{
			size_t blocks = len / 16;
			size_t bytes = blocks * 16;
			const uint8_t* prev = iv_;

			for (size_t i = 0; i < blocks; i++)
			{
				xor_block_128(in, prev, block_);
				cipher_->encryptBlock(block_, out);

				//cipher_->encryptBlock(in, out);
				prev = out;
				in += 16;
				out += 16;
			}
			memcpy(iv_, out-16, 16);
			resultlen += bytes;
			len -= bytes;
		}
		else if (nb == 32) // optimization for the most common block sizes
		{
			size_t blocks = len / 32;
			size_t bytes = blocks * 32;
			const uint8_t* prev = iv_;
			for (size_t i = 0; i < blocks; i++)
			{
				xor_block_256(in, prev, block_);
				cipher_->encryptBlock(block_, out);
				prev = out;
				in += 32;
				out += 32;
			}
			memcpy(iv_, out-32, 32);
			resultlen += bytes;
			len -= bytes;
		}
		else
		{
			size_t blocks = len / nb;
			size_t bytes = blocks * nb;
			for (size_t i = 0; i < blocks; i++)
			{
				for (unsigned int i = 0; i < nb; i++)
					block_[i] = in[i] ^ iv_[i];
				cipher_->encryptBlock(block_, out);
				memcpy(iv_, out, nb);
				in += nb;
				out += nb;
			}
			resultlen += bytes;
			len -= bytes;
		}
	}
	// TODO possible xor with iv directly here and in the first if instead of memcpy
	memcpy(block_+pos, in, len);
	pos += len;
}

void cbc::encryptFinal(uint8_t* out, size_t& resultlen)
{
	int padding = nb_ - static_cast<int>(pos);
	memset(block_ + pos, padding, padding);
	for (int i = 0; i < nb_; i++)
		block_[i] ^= iv_[i];
	cipher_->encryptBlock(block_, out);
	resultlen = nb_;
}

void cbc::decryptUpdate(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen)
{
	resultlen = 0;
	unsigned int nb = nb_;
	if (pos && pos + len > nb)
	{
		memcpy(block_ + pos, in, nb - pos);
		cipher_->decryptBlock(block_, out);
		for (unsigned int i = 0; i < nb; i++)
			out[i] ^= iv_[i];
		memcpy(iv_, block_, nb);
		in += nb - pos;
		len -= nb - pos;
		out += nb;
		resultlen += nb;
		pos = 0;
	}
	if (len > nb)
	{
		if (nb == 16) // optimization for the most common block sizes
		{
			size_t blocks = (len-1) / 16;
			size_t bytes = blocks * 16;
			const uint8_t* prev = iv_;

			for (size_t i = 0; i < blocks; i++)
			{
				cipher_->decryptBlock(in, block_);
				xor_block_128(block_, prev, out);

				prev = in;
				in += 16;
				out += 16;
			}
			memcpy(iv_, in - 16, 16);
			resultlen += bytes;
			len -= bytes;
		}
		else if (nb == 32) // optimization for the most common block sizes
		{
			size_t blocks = (len-1) / 32;
			size_t bytes = blocks * 32;
			const uint8_t* prev = iv_;
			for (size_t i = 0; i < blocks; i++)
			{
				cipher_->decryptBlock(in, block_);
				xor_block_256(block_, prev, out);
				prev = in;
				in += 32;
				out += 32;
			}
			memcpy(iv_, in - 32, 32);
			resultlen += bytes;
			len -= bytes;
		}
		else
		{
			size_t blocks = (len-1) / nb;
			size_t bytes = blocks * nb;
			for (size_t i = 0; i < blocks; i++)
			{
				cipher_->decryptBlock(in, block_);
				for (unsigned int i = 0; i < nb; i++)
					out[i] = block_[i] ^ iv_[i];
				memcpy(iv_, in, nb);
				in += nb;
				out += nb;
			}
			resultlen += bytes;
			len -= bytes;
		}
	}
	// TODO possible xor with iv directly here and in the first if instead of memcpy
	memcpy(block_ + pos, in, len);
	pos += len;
}

void cbc::decryptFinal(uint8_t* out, size_t& resultlen)
{
	assert(pos == nb_);
	cipher_->decryptBlock(block_, block_);
	for (int i = 0; i < nb_; i++)
		block_[i] ^= iv_[i];
	int padding = block_[pos - 1];
	resultlen = nb_ - padding;
	memcpy(out, block_, resultlen);
}

}
