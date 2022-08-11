/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "sha3.h"
#include "portability.h"
#include <memory.h>
#include <algorithm>
#include <functional>

#ifdef _MSC_VER
#define inline __forceinline
#endif
//#define NO_OPTIMIZED_VERSIONS

namespace cppcrypto
{
	static const uint64_t RC[24] =
	{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

	void sha3::init()
	{
		if (impl_)
			return impl_->init(static_cast<unsigned int>(rate), static_cast<unsigned int>(hs * 2));

		memset(A, 0, sizeof(A));
		pos = 0;
	}

	void sha3::update(const unsigned char* data, size_t len)
	{
		if (impl_)
			return impl_->update(data, len);

		size_t r = rate / 8;
		if (pos && pos + len >= r)
		{
			memcpy(m + pos, data, r - pos);
			transform(m, 1);
			len -= r - pos;
			data += r - pos;
			pos = 0;
		}
		if (len >= r)
		{
			size_t blocks = len / r;
			size_t bytes = blocks * r;
			transform((void*)data, blocks);
			len -= bytes;
			data += bytes;
		}
		memcpy(m + pos, data, len);
		pos += len;
	}

	static inline void dotransform(uint64_t* A)
	{
		for (int round = 0; round < 24; round++)
		{
			uint64_t C[5], D[5];
			C[0] = A[0 * 5 + 0] ^ A[1 * 5 + 0] ^ A[2 * 5 + 0] ^ A[3 * 5 + 0] ^ A[4 * 5 + 0];
			C[1] = A[0 * 5 + 1] ^ A[1 * 5 + 1] ^ A[2 * 5 + 1] ^ A[3 * 5 + 1] ^ A[4 * 5 + 1];
			C[2] = A[0 * 5 + 2] ^ A[1 * 5 + 2] ^ A[2 * 5 + 2] ^ A[3 * 5 + 2] ^ A[4 * 5 + 2];
			C[3] = A[0 * 5 + 3] ^ A[1 * 5 + 3] ^ A[2 * 5 + 3] ^ A[3 * 5 + 3] ^ A[4 * 5 + 3];
			C[4] = A[0 * 5 + 4] ^ A[1 * 5 + 4] ^ A[2 * 5 + 4] ^ A[3 * 5 + 4] ^ A[4 * 5 + 4];

			D[0] = C[4] ^ rotatel64(C[1], 1);
			D[1] = C[0] ^ rotatel64(C[2], 1);
			D[2] = C[1] ^ rotatel64(C[3], 1);
			D[3] = C[2] ^ rotatel64(C[4], 1);
			D[4] = C[3] ^ rotatel64(C[0], 1);

			uint64_t B0 = A[0 * 5 + 0] ^ D[0];
			uint64_t B10 = rotatel64(A[0 * 5 + 1] ^ D[1], 1);
			uint64_t B20 = rotatel64(A[0 * 5 + 2] ^ D[2], 62);
			uint64_t B5 = rotatel64(A[0 * 5 + 3] ^ D[3], 28);
			uint64_t B15 = rotatel64(A[0 * 5 + 4] ^ D[4], 27);

			uint64_t B16 = rotatel64(A[1 * 5 + 0] ^ D[0], 36);
			uint64_t B1 = rotatel64(A[1 * 5 + 1] ^ D[1], 44);
			uint64_t B11 = rotatel64(A[1 * 5 + 2] ^ D[2], 6);
			uint64_t B21 = rotatel64(A[1 * 5 + 3] ^ D[3], 55);
			uint64_t B6 = rotatel64(A[1 * 5 + 4] ^ D[4], 20);

			uint64_t B7 = rotatel64(A[2 * 5 + 0] ^ D[0], 3);
			uint64_t B17 = rotatel64(A[2 * 5 + 1] ^ D[1], 10);
			uint64_t B2 = rotatel64(A[2 * 5 + 2] ^ D[2], 43);
			uint64_t B12 = rotatel64(A[2 * 5 + 3] ^ D[3], 25);
			uint64_t B22 = rotatel64(A[2 * 5 + 4] ^ D[4], 39);

			uint64_t B23 = rotatel64(A[3 * 5 + 0] ^ D[0], 41);
			uint64_t B8 = rotatel64(A[3 * 5 + 1] ^ D[1], 45);
			uint64_t B18 = rotatel64(A[3 * 5 + 2] ^ D[2], 15);
			uint64_t B3 = rotatel64(A[3 * 5 + 3] ^ D[3], 21);
			uint64_t B13 = rotatel64(A[3 * 5 + 4] ^ D[4], 8);

			uint64_t B14 = rotatel64(A[4 * 5 + 0] ^ D[0], 18);
			uint64_t B24 = rotatel64(A[4 * 5 + 1] ^ D[1], 2);
			uint64_t B9 = rotatel64(A[4 * 5 + 2] ^ D[2], 61);
			uint64_t B19 = rotatel64(A[4 * 5 + 3] ^ D[3], 56);
			uint64_t B4 = rotatel64(A[4 * 5 + 4] ^ D[4], 14);

			A[0 * 5 + 0] = B0 ^ ((~B1) & B2);
			A[0 * 5 + 1] = B1 ^ ((~B2) & B3);
			A[0 * 5 + 2] = B2 ^ ((~B3) & B4);
			A[0 * 5 + 3] = B3 ^ ((~B4) & B0);
			A[0 * 5 + 4] = B4 ^ ((~B0) & B1);

			A[1 * 5 + 0] = B5 ^ ((~B6) & B7);
			A[1 * 5 + 1] = B6 ^ ((~B7) & B8);
			A[1 * 5 + 2] = B7 ^ ((~B8) & B9);
			A[1 * 5 + 3] = B8 ^ ((~B9) & B5);
			A[1 * 5 + 4] = B9 ^ ((~B5) & B6);

			A[2 * 5 + 0] = B10 ^ ((~B11) & B12);
			A[2 * 5 + 1] = B11 ^ ((~B12) & B13);
			A[2 * 5 + 2] = B12 ^ ((~B13) & B14);
			A[2 * 5 + 3] = B13 ^ ((~B14) & B10);
			A[2 * 5 + 4] = B14 ^ ((~B10) & B11);

			A[3 * 5 + 0] = B15 ^ ((~B16) & B17);
			A[3 * 5 + 1] = B16 ^ ((~B17) & B18);
			A[3 * 5 + 2] = B17 ^ ((~B18) & B19);
			A[3 * 5 + 3] = B18 ^ ((~B19) & B15);
			A[3 * 5 + 4] = B19 ^ ((~B15) & B16);

			A[4 * 5 + 0] = B20 ^ ((~B21) & B22);
			A[4 * 5 + 1] = B21 ^ ((~B22) & B23);
			A[4 * 5 + 2] = B22 ^ ((~B23) & B24);
			A[4 * 5 + 3] = B23 ^ ((~B24) & B20);
			A[4 * 5 + 4] = B24 ^ ((~B20) & B21);

			A[0] ^= RC[round];
		}
	}

	void sha3::transform(void* mp, uint64_t num_blks)
	{
		size_t r = rate / 8;
		size_t r64 = rate / 64;
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			for (size_t i = 0; i < r64; i++)
				A[i] ^= reinterpret_cast<const uint64_t*>((char*)mp+blk*r)[i];

			dotransform(A);
		}
	}

	void sha3::final(unsigned char* hash)
	{
		if (impl_)
			return impl_->final(hash, hs);
		size_t r = rate / 8;
		m[pos++] = 0x06;
		memset(m + pos, 0, r - pos);
		m[r - 1] |= 0x80;
		transform(m, 1);
		memcpy(hash, A, hashsize() / 8);
	}

	sha3::sha3(size_t hashsize)
		: m(nullptr), hs(hashsize)
	{
		validate_hash_size(hashsize, {224, 256, 384, 512});

		rate = 1600U - hs * 2;

#ifndef NO_OPTIMIZED_VERSIONS
//#ifdef _M_X64
		if (cpu_info::avx2())
			impl_.create<detail::sha3_impl_avx2>();
		else if (cpu_info::ssse3())
			impl_.create<detail::sha3_impl_ssse3>();
		else
//#endif
#endif
			m = new unsigned char[rate / 8];
	}

	sha3::~sha3()
	{
		clear();
		delete[] m;
	}

	void sha3::clear()
	{
		zero_memory(A, sizeof(A));
		if (m)
			zero_memory(m, rate / 8);
	}

	shake128::shake128(size_t hashsize, const std::string& function_name, const std::string& customization)
		: shake256(hashsize, function_name, customization)
	{
		validate_hash_size(hashsize, SIZE_MAX);
		hs = 128;
		rate = 1600U - 128 * 2;
		if (m)
		{
			delete[] m;
			m = new unsigned char[rate / 8];
		}

	}

	shake256::shake256(size_t hashsize, const std::string& function_name, const std::string& customization)
		: sha3(256), size(hashsize), N(function_name), S(customization)
	{
		validate_hash_size(hashsize, SIZE_MAX);
	}

	static inline size_t left_encode(size_t num, unsigned char* buf)
	{
		// first, calculate length
		unsigned char n = 1;
		size_t tmp = num;
		while (tmp >>= 8)
			++n;
		buf[0] = n;
		size_t result = n + 1;
		size_t i = 0;
		while (n)
			buf[n--] = static_cast<unsigned char>(num >> (8*i++));
		return result;
	}

	void shake256::init()
	{
		sha3::init();
		if (impl_)
			impl_->set_padding_byte(N.empty() && S.empty() ? 0x1F : 0x04);
		if (!N.empty() || !S.empty())
		{
			unsigned char buf[1024];
			size_t r = rate / 8;
			size_t len = left_encode(r, buf);

#ifdef CPPCRYPTO_DEBUG
			for (size_t b = 0; b < len; b++)
				printf("%02x ", (unsigned char)buf[b]);
#endif

			size_t total = len;
			update(buf, len);
			len = left_encode(N.length() * 8, buf);

#ifdef CPPCRYPTO_DEBUG
			for (size_t b = 0; b < len; b++)
				printf("%02x ", (unsigned char)buf[b]);
#endif

			total += len;
			update(buf, len);
			if (!N.empty())
				update(reinterpret_cast<unsigned char*>(&N[0]), N.length());
			len = left_encode(S.length() * 8, buf);

#ifdef CPPCRYPTO_DEBUG
			for (size_t b = 0; b < len; b++)
				printf("%02x ", (unsigned char)buf[b]);
#endif

			update(buf, len);
			total += len;
			if (!S.empty())
				update(reinterpret_cast<unsigned char*>(&S[0]), S.length());

#ifdef CPPCRYPTO_DEBUG
			for (size_t b = 0; b < S.length(); b++)
				printf("%02x ", (unsigned char)S[b]);
#endif

			total += S.length() + N.length();

			len = r - (total % r);
			memset(buf, 0, len);

#ifdef CPPCRYPTO_DEBUG
			for (size_t b = 0; b < len; b++)
				printf("%02x ", (unsigned char)buf[b]);
#endif

			update(buf, len);
		}
	}

	void shake256::final(unsigned char* hash)
	{
		if (impl_)
			return impl_->final(hash, hashsize());
		size_t r = rate / 8;
		m[pos++] = N.empty() && S.empty() ? 0x1F : 0x04;
		memset(m + pos, 0, r - pos);
		m[r - 1] |= 0x80;
		transform(m, 1);
		size_t processed = 0;
		while (processed < hashsize())
		{
			if (processed)
				dotransform(A);
			size_t to_copy = std::min(hashsize(), rate);
			memcpy(hash + processed / 8, A, to_copy / 8);
			processed += to_copy;
		}
	}

}

