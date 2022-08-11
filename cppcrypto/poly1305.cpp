/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "poly1305.h"
#include <memory.h>
#include <assert.h>
#include "portability.h"
#include "cpuinfo.h"
#include <iostream>

//#define NO_OPTIMIZED_VERSIONS

namespace cppcrypto
{
	poly1305::poly1305(const std::string& key)
	{
		construct(reinterpret_cast<const unsigned char*>(&key[0]), key.length());
	}

	poly1305::poly1305(const unsigned char* key, size_t keylen)
	{
		construct(key, keylen);
	}

	void poly1305::construct(const unsigned char* key, size_t keylen)
	{
		assert(keylen == 32);

		memcpy(key_, key, 32);
		memcpy(r_, key, 16);
		r_[3] &= 0x0f;
		r_[7] &= 0x0f;
		r_[11] &= 0x0f;
		r_[15] &= 0x0f;
		r_[4] &= 0xfc;
		r_[8] &= 0xfc;
		r_[12] &= 0xfc;
		r_[16] = 0;

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
			impl_.create<detail::poly1305_impl_sse2>();
#endif
	}

	poly1305::~poly1305()
	{
		clear();
		zero_memory(r_, r_.bytes());
		zero_memory(key_, key_.bytes());
		zero_memory(m_, m_.bytes());
		zero_memory(accumulator_, accumulator_.bytes());
		if (impl_)
			impl_->clear();
	}

	// This implementation is based on the public domain code from poly1305-donna by Andrew Moon
	// See https://github.com/floodyberry/poly1305-donna

	static inline void add(unsigned char* accumulator, const unsigned char* M)
	{
		for (uint16_t res = 0, i = 0; i < 17; i++)
		{
			res += static_cast<uint16_t>(accumulator[i] + static_cast<uint16_t>(M[i]));
			accumulator[i] = static_cast<unsigned char>(res);
			res >>= 8;
		}
	}

	static inline void multiply(unsigned char* accumulator, unsigned char* r, unsigned long* th)
	{
		for (int i = 0; i < 17; i++)
		{
			uint32_t u = 0;
			for (int j = 0; j <= i; j++)
				u += (unsigned short)accumulator[j] * r[i - j];
			for (int j = i + 1; j < 17; j++)
			{
				unsigned long v = (unsigned short)accumulator[j] * r[i + 17 - j];
				v = ((v << 8) + (v << 6)); /* v *= (5 << 6); */
				u += v;
			}
			th[i] = u;
		}
	}

	static inline void reduce(unsigned char* h, unsigned long* hr)
	{
		unsigned long u = 0;
		for (int i = 0; i < 16; i++)
		{
			u += hr[i];
			h[i] = static_cast<unsigned char>(u);
			u >>= 8;
		}
		u += hr[16];
		h[16] = static_cast<unsigned char>(u) & 0x03;
		u >>= 2;
		u += (u << 2);
		for (int i = 0; i < 16; i++)
		{
			u += h[i];
			h[i] = static_cast<unsigned char>(u);
			u >>= 8;
		}
		h[16] += static_cast<unsigned char>(u);
	}

	static inline void full_reduce(unsigned char* h)
	{
		static const unsigned char minusp[17] = {
			0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xfc
		};
		unsigned char horig[17], negative;

		memcpy(horig, h, 17);
		add(h, minusp);
		negative = -(h[16] >> 7);
		for (int i = 0; i < 17; i++)
			h[i] ^= negative & (horig[i] ^ h[i]);
	}


	void poly1305::transform(const unsigned char* mp, size_t num_blks, bool incomplete)
	{
		for (size_t blk = 0; blk < num_blks; blk++)
		{
			unsigned char M[17];
			unsigned long th[17];
			memcpy(M, mp, 17);
			if (!incomplete)
				M[16] = 1;

#ifdef CPPCRYPTO_DEBUG
			printf("block: ");
			for (int i = 0; i < 17; i++)
				printf("%02x", M[16-i]);
			printf("\n");
#endif

			// Add this number to accumulator
			add(accumulator_, M);

#ifdef CPPCRYPTO_DEBUG
			printf("added: ");
			for (int i = 0; i < 17; i++)
				printf("%02x", accumulator[16-i]);
			printf("\n");
#endif

			// Multiply by r
			multiply(accumulator_, r_, th);

#ifdef CPPCRYPTO_DEBUG
			printf("multiplied: ");
			for (int i = 0; i < sizeof(th); i++)
				printf("%02x", ((unsigned char*)th)[i]);
			printf("\n");
#endif

			// Set the accumulator to the result modulo p
			reduce(accumulator_, th);

#ifdef CPPCRYPTO_DEBUG
			printf("accumulator: ");
			for (int i = 0; i < 17; i++)
				printf("%02x", accumulator[16-i]);
			printf("\n");
#endif

			mp += 16;
		}
	}

	void poly1305::update(const unsigned char* data, size_t len)
	{
		size_t bs = impl_ ? impl_->blockbytes() : 16;
		if (pos && pos + len >= bs)
		{
			memcpy(&m_[0] + pos, data, bs - pos);
			if (impl_)
				impl_->transform(&m_[0], bs);
			else
				transform(&m_[0], 1, false);
			len -= bs - pos;
			data += bs - pos;
			pos = 0;
		}
		if (len >= bs)
		{
			size_t blocks = len / bs;
			size_t bytes = blocks * bs;
			if (!impl_)
				transform(data, blocks, false);
			else
				impl_->transform(data, bytes);
			len -= bytes;
			data += bytes;
		}
		memcpy(&m_[pos], data, len);
		pos += len;
	}

	void poly1305::init()
	{
		if (impl_)
			impl_->init(key_);
		pos = 0;
		memset(accumulator_, 0, accumulator_.bytes());

#ifdef CPPCRYPTO_DEBUG
		printf("r: ");
		for (int i = 0; i < 17; i++)
			printf("%02x", r[16-i]);
		printf("\n");

		printf("s: ");
		for (int i = 0; i < 16; i++)
			printf("%02x", s[15 - i]);
		printf("\n");
#endif
	};

	void poly1305::final(unsigned char* hash)
	{
		if (impl_)
			return impl_->finish(&m_[0], pos, hash);

		if (pos)
		{
			m_[pos++] = 0x01;
			memset(&m_[pos], 0, m_.bytes() - pos);
			transform(m_, 1, true);
		}

		full_reduce(accumulator_);
		add(accumulator_, key_+16);
		memcpy(hash, accumulator_, 16);
	}

	poly1305* poly1305::clone() const
	{
		return new poly1305(key_.get(), 32);
	}

	void poly1305::clear()
	{
		pos = 0;
		zero_memory(accumulator_, accumulator_.bytes());
	}

}
