/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "portability.h"
#include "blake.h"
#include <memory.h>
#include <functional>
#include <stdexcept>

//#define CPPCRYPTO_DEBUG
//#define NO_OPTIMIZED_VERSIONS

#ifdef _MSC_VER
#define inline __forceinline
#endif

extern "C"
{
	int blake256_compress_sse41(uint32_t* h, int padding, uint64_t total, const unsigned char * datablock);
	int blake256_compress_sse2(uint32_t* h, int padding, uint64_t total, const unsigned char * datablock);
	int blake512_compress_sse2(uint64_t* h, uint64_t t0, int padding, const unsigned char* datablock);
	int blake512_compress_sse41(uint64_t* h, uint64_t t0, int padding, const unsigned char* datablock);
#ifdef _M_X64
	int blake256_compress_avxs(uint32_t* h, const unsigned char * datablock, uint64_t padding, uint32_t* total);
#endif
}

namespace cppcrypto
{

	static const uint32_t c[16] = {
		0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
		0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
	};

	static const uint32_t S[10][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
	};

	static inline uint32_t rotrblk(uint32_t x, int n)
	{
		return (x >> n) | (x << (32 - n));
	}

	static inline void G(int r, int i, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M)
	{
		a = a + b + (M[S[r % 10][2 * i]] ^ (cppcrypto::c)[S[r % 10][2 * i + 1]]);
		d = rotrblk(d ^ a, 16);
		c = c + d;
		b = rotrblk(b ^ c, 12);
		a = a + b + (M[S[r % 10][2 * i + 1]] ^ (cppcrypto::c)[S[r % 10][2 * i]]);
		d = rotrblk(d ^ a, 8);
		c = c + d;
		b = rotrblk(b ^ c, 7);
	}

	static inline void round(int r, uint32_t* M, uint32_t* v) 
	{
		G(r, 0, v[0], v[4], v[8], v[12], M);
		G(r, 1, v[1], v[5], v[9], v[13], M);
		G(r, 2, v[2], v[6], v[10], v[14], M);
		G(r, 3, v[3], v[7], v[11], v[15], M);
		G(r, 4, v[0], v[5], v[10], v[15], M);
		G(r, 5, v[1], v[6], v[11], v[12], M);
		G(r, 6, v[2], v[7], v[8], v[13], M);
		G(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}

	void blake::transform256(bool padding)
	{
		uint32_t M[16];
		for (uint32_t i = 0; i < 64 / 4; i++)
		{
			M[i] = swap_uint32((reinterpret_cast<const uint32_t*>(m.get())[i]));
		}
#ifdef	CPPCRYPTO_DEBUG
		printf("M1 - M8: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint32_t t0 = static_cast<uint32_t>(total);
		uint32_t t1 = static_cast<uint32_t>((total) >> 32);
		if (padding)
			t0 = t1 = 0;


#ifdef	CPPCRYPTO_DEBUG
		printf("t0: %08X (%d), t1: %08X\n", t0, t0, t1);
#endif

		uint32_t v[16];
		memcpy(v, u.H256, sizeof(uint32_t) * 8);
		v[8 + 0] = u.H256[8] ^ c[0];
		v[8 + 1] = u.H256[9] ^ c[1];
		v[8 + 2] = u.H256[10] ^ c[2];
		v[8 + 3] = u.H256[11] ^ c[3];
		v[12] = t0 ^ c[4];
		v[13] = t0 ^ c[5];
		v[14] = t1 ^ c[6];
		v[15] = t1 ^ c[7];

#ifdef	CPPCRYPTO_DEBUG
		printf("v0 - v15: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		// The loop is fully unrolled for performance reasons
		round(0, M, v);
		round(1, M, v);
		round(2, M, v);
		round(3, M, v);
		round(4, M, v);
		round(5, M, v);
		round(6, M, v);
		round(7, M, v);
		round(8, M, v);
		round(9, M, v);
		round(10, M, v);
		round(11, M, v);
		round(12, M, v);
		round(13, M, v);

		u.H256[0] = u.H256[0] ^ u.H256[8] ^ v[0] ^ v[0 + 8];
		u.H256[0 + 4] = u.H256[0 + 4] ^ u.H256[8] ^ v[0 + 4] ^ v[0 + 8 + 4];
		u.H256[1] = u.H256[1] ^ u.H256[9] ^ v[1] ^ v[1 + 8];
		u.H256[1 + 4] = u.H256[1 + 4] ^ u.H256[9] ^ v[1 + 4] ^ v[1 + 8 + 4];
		u.H256[2] = u.H256[2] ^ u.H256[10] ^ v[2] ^ v[2 + 8];
		u.H256[2 + 4] = u.H256[2 + 4] ^ u.H256[10] ^ v[2 + 4] ^ v[2 + 8 + 4];
		u.H256[3] = u.H256[3] ^ u.H256[11] ^ v[3] ^ v[3 + 8];
		u.H256[3 + 4] = u.H256[3 + 4] ^ u.H256[11] ^ v[3 + 4] ^ v[3 + 8 + 4];

#ifdef	CPPCRYPTO_DEBUG
		printf("H[0] - H[7]: %08X %08X %08X %08X %08X %08X %08X %08X\n",
			u.H256[0], u.H256[1], u.H256[2], u.H256[3], u.H256[4], u.H256[5], u.H256[6], u.H256[7]);
#endif
	}

	void blake::update(const unsigned char* data, size_t len)
	{
		size_t blockbytes = blocksize() / 8;
		while (pos + len >= blockbytes)
		{
			memcpy(m + pos, data, blockbytes - pos);
			len -= blockbytes - pos;
			total += (blockbytes - pos) * 8;
			transfunc(false);
			data += blockbytes - pos;
			pos = 0;
		}
		memcpy(m+pos, data, len);
		pos += len;
		total += len * 8;
	}


	static const uint64_t c512[16] = {
		0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
		0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
		0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
		0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69
	};

	void blake::init()
	{
		pos = 0;
		total = 0;
		switch(hs)
		{
			case 512:
				u.H512[0] = 0x6A09E667F3BCC908;
				u.H512[1] = 0xBB67AE8584CAA73B;
				u.H512[2] = 0x3C6EF372FE94F82B;
				u.H512[3] = 0xA54FF53A5F1D36F1;
				u.H512[4] = 0x510E527FADE682D1;
				u.H512[5] = 0x9B05688C2B3E6C1F;
				u.H512[6] = 0x1F83D9ABFB41BD6B;
				u.H512[7] = 0x5BE0CD19137E2179;
				break;
			case 384:
				u.H512[0] = 0xcbbb9d5dc1059ed8;
				u.H512[1] = 0x629a292a367cd507;
				u.H512[2] = 0x9159015a3070dd17;
				u.H512[3] = 0x152fecd8f70e5939;
				u.H512[4] = 0x67332667ffc00b31;
				u.H512[5] = 0x8eb44a8768581511;
				u.H512[6] = 0xdb0c2e0d64f98fa7;
				u.H512[7] = 0x47b5481dbefa4fa4;
				break;
			case 256:
				u.H256[0] = 0x6a09e667;
				u.H256[1] = 0xbb67ae85;
				u.H256[2] = 0x3c6ef372;
				u.H256[3] = 0xa54ff53a;
				u.H256[4] = 0x510e527f;
				u.H256[5] = 0x9b05688c;
				u.H256[6] = 0x1f83d9ab;
				u.H256[7] = 0x5be0cd19;
				break;
			case 224:
				u.H256[0] = 0xC1059ED8;
				u.H256[1] = 0x367CD507;
				u.H256[2] = 0x3070DD17;
				u.H256[3] = 0xF70E5939;
				u.H256[4] = 0xFFC00B31;
				u.H256[5] = 0x68581511;
				u.H256[6] = 0x64F98FA7;
				u.H256[7] = 0xBEFA4FA4;
				break;
		}
	};

	static inline void G512(int r, int i, uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t* M) 
	{
		a = a + b + (M[S[r % 10][2 * i]] ^ (c512)[S[r % 10][2 * i + 1]]);
		d = rotater64(d ^ a, 32);
		c = c + d;
		b = rotater64(b ^ c, 25);
		a = a + b + (M[S[r % 10][2 * i + 1]] ^ (c512)[S[r % 10][2 * i]]);
		d = rotater64(d ^ a, 16);
		c = c + d;
		b = rotater64(b ^ c, 11);
	}

	static inline void round512(int r, uint64_t* M, uint64_t* v) 
	{
		G512(r, 0, v[0], v[4], v[8], v[12], M);
		G512(r, 1, v[1], v[5], v[9], v[13], M);
		G512(r, 2, v[2], v[6], v[10], v[14], M);
		G512(r, 3, v[3], v[7], v[11], v[15], M);
		G512(r, 4, v[0], v[5], v[10], v[15], M);
		G512(r, 5, v[1], v[6], v[11], v[12], M);
		G512(r, 6, v[2], v[7], v[8], v[13], M);
		G512(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	CPPCRYPTO_DEBUG
		printf("round %d v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}

	void blake::transform512(bool padding)
	{
		uint64_t M[16];
		for (uint32_t i = 0; i < 128 / 8; i++)
		{
			M[i] = swap_uint64((reinterpret_cast<const uint64_t*>(m.get())[i]));
		}
#ifdef	CPPCRYPTO_DEBUG
		printf("M1 - M8: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint64_t t0 = total;
		uint64_t t1 = 0ULL;
		if (padding)
			t0 = t1 = 0;

#ifdef	CPPCRYPTO_DEBUG
		printf("t0: %016llx (%d), t1: %016llx\n", t0, t0, t1);
#endif

		uint64_t v[16];
		memcpy(v, u.H512, sizeof(uint64_t)*8);
		v[8 + 0] = u.H512[8] ^ c512[0];
		v[8 + 1] = u.H512[9] ^ c512[1];
		v[8 + 2] = u.H512[10] ^ c512[2];
		v[8 + 3] = u.H512[11] ^ c512[3];
		v[12] = t0 ^ c512[4];
		v[13] = t0 ^ c512[5];
		v[14] = t1 ^ c512[6];
		v[15] = t1 ^ c512[7];

#ifdef	CPPCRYPTO_DEBUG
		printf("v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		// The loop is fully unrolled for performance reasons
		round512(0, M, v);
		round512(1, M, v);
		round512(2, M, v);
		round512(3, M, v);
		round512(4, M, v);
		round512(5, M, v);
		round512(6, M, v);
		round512(7, M, v);
		round512(8, M, v);
		round512(9, M, v);
		round512(10, M, v);
		round512(11, M, v);
		round512(12, M, v);
		round512(13, M, v);
		round512(14, M, v);
		round512(15, M, v);

		u.H512[0] = u.H512[0] ^ u.H512[8] ^ v[0] ^ v[0 + 8];
		u.H512[0 + 4] = u.H512[0 + 4] ^ u.H512[8] ^ v[0 + 4] ^ v[0 + 8 + 4];
		u.H512[1] = u.H512[1] ^ u.H512[9] ^ v[1] ^ v[1 + 8];
		u.H512[1 + 4] = u.H512[1 + 4] ^ u.H512[9] ^ v[1 + 4] ^ v[1 + 8 + 4];
		u.H512[2] = u.H512[2] ^ u.H512[10] ^ v[2] ^ v[2 + 8];
		u.H512[2 + 4] = u.H512[2 + 4] ^ u.H512[10] ^ v[2 + 4] ^ v[2 + 8 + 4];
		u.H512[3] = u.H512[3] ^ u.H512[11] ^ v[3] ^ v[3 + 8];
		u.H512[3 + 4] = u.H512[3 + 4] ^ u.H512[11] ^ v[3 + 4] ^ v[3 + 8 + 4];

#ifdef	CPPCRYPTO_DEBUG
		printf("u.H512[0] - u.H512[7]: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			u.H512[0], u.H512[1], u.H512[2], u.H512[3], u.H512[4], u.H512[5], u.H512[6], u.H512[7]);
#endif
	}

	void blake::final(unsigned char* hash)
	{
		size_t blockbytes = blocksize() / 8;
		size_t messageend = hs > 256 ? 111 : 55;
		bool truncated = hs != 512 && hs != 256;
		bool padding = !pos;
		m[pos] = pos == messageend && !truncated ? 0x81 : 0x80;
		if (pos++ > messageend)
		{
			memset(m + pos, 0, blockbytes - pos);
			transfunc(false);
			pos = 0;
			padding = true;
		}
		if (pos <= messageend)
		{
			memset(m + pos, 0, messageend - pos);
			m[messageend] = truncated ? 0x00 : 0x01;
		}
		uint64_t mlen = swap_uint64(total);
		if (blockbytes == 128)
			memset(m + (128 - 16), 0, sizeof(uint64_t));
		memcpy(m + (blockbytes - 8), &mlen, sizeof(uint64_t));
		transfunc(padding);
		if (hs > 256)
		{
			for (int i = 0; i < 8; i++)
			{
				u.H512[i] = swap_uint64(u.H512[i]);
			}
			memcpy(hash, u.H512, hashsize()/8);
		}
		else
		{
			for (int i = 0; i < 8; i++)
			{
				u.H256[i] = swap_uint32(u.H256[i]);
			}
			memcpy(hash, u.H256, hashsize()/8);
		}
	}

	void blake::validate_salt_length(size_t saltlen) const
	{
		if (saltlen && ((hs > 256 && saltlen != 32) || (hs <= 256 && saltlen != 16)))
			throw std::runtime_error("invalid salt length");
	}

	blake::blake(size_t hashsize, const unsigned char* salt, size_t saltlen) : hs(hashsize)
	{
		validate_hash_size(hashsize, {224, 256, 384, 512});
		validate_salt_length(saltlen);
		if (hs > 256)
		{
			// H[8]..H12] reserved for salt
			u.H512 = static_cast<uint64_t*>(aligned_allocate(sizeof(uint64_t) * 12, 64));
			if (saltlen)
				for (int i = 0; i < 4; i++)
					u.H512[8 + i] = swap_uint64((reinterpret_cast<const uint64_t*>(salt)[i]));
			else 
				u.H512[8] = u.H512[9] = u.H512[10] = u.H512[11] = 0;
#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse41() && !saltlen)
			transfunc = [this](bool padding) { blake512_compress_sse41(u.H512, total, padding, m); };
		else if (cpu_info::sse2() && !saltlen)
			transfunc = [this](bool padding) { blake512_compress_sse2(u.H512, total, padding, m); };
		else
#endif
#ifdef NO_BIND_TO_FUNCTION
			transfunc = [this](bool padding) { transform512(padding); };
#else
			transfunc = std::bind(&blake::transform512, this, std::placeholders::_1);
#endif
		}
		else
		{
			// H[8]..H12] reserved for salt
			u.H256 = static_cast<uint32_t*>(aligned_allocate(sizeof(uint32_t) * 12, 64));
			if (saltlen)
				for (int i = 0; i < 4; i++)
					u.H256[8 + i] = swap_uint32((reinterpret_cast<const uint32_t*>(salt)[i]));
			else 
				u.H256[8] = u.H256[9] = u.H256[10] = u.H256[11] = 0;
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef _M_X64
			if (cpu_info::avx() && !saltlen && false)
				transfunc = [this](bool padding) {
				uint32_t t[2];
				if (!padding)
				{
					t[0] = static_cast<uint32_t>(total);
					t[1] = static_cast<uint32_t>((total) >> 32);
				}

				blake256_compress_avxs(u.H256, m, padding, t); 
				//_mm256_zeroall();
				};
			else
#endif
			if (cpu_info::sse41() && !saltlen)
				transfunc = [this](bool padding) { blake256_compress_sse41(u.H256, padding, total, m); };
			else if (cpu_info::sse2() && !saltlen)
				transfunc = [this](bool padding) { blake256_compress_sse2(u.H256, padding, total, m); };
			else
#endif
#ifdef NO_BIND_TO_FUNCTION
				transfunc = [this](bool padding) { transform256(padding); };
#else
				transfunc = std::bind(&blake::transform256, this, std::placeholders::_1);
#endif
		}
	}

	blake::~blake()
	{
		clear();
		if (hs > 256)
			aligned_deallocate(u.H512);
		else
			aligned_deallocate(u.H256);
	}

	void blake::clear()
	{
		if (hs > 256)
			zero_memory(u.H512, sizeof(uint64_t) * 12);
		else
			zero_memory(u.H256, sizeof(uint32_t) * 12);
		zero_memory(m.get(), m.bytes());
	}

	blake* blake::clone() const
	{
		bool has_salt = false;
		if (hs > 256)
		{
			if (u.H512[8] || u.H512[9] || u.H512[10] || u.H512[11])
				has_salt = true;
		}
		else
		{
			if (u.H256[8] || u.H256[9] || u.H256[10] || u.H256[11])
				has_salt = true;
		}
		if (!has_salt)
			return new blake(hs);

		unsigned char salt[sizeof(uint64_t) * 4];
		size_t saltlen = hs > 256 ? 32 : 16;
		for (int i = 0; i < 4; i++)
		{
			if (hs > 256)
			{
				uint64_t sp = swap_uint64(u.H512[8 + i]);
				memcpy(salt + sizeof(uint64_t) * i, &sp, sizeof(uint64_t));
			}
			else
			{
				uint32_t sp = swap_uint32(u.H256[8 + i]);
				memcpy(salt + sizeof(uint32_t) * i, &sp, sizeof(uint32_t));
			}
		}
		return new blake(hs, salt, saltlen);
	}
}

