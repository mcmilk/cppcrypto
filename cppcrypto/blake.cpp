/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "cpuinfo.h"
#include "blake.h"

//#define DEBUG

extern "C"
{
	int blake256_compress_sse41(uint32_t* h, int padding, uint64_t total, const uint8_t * datablock);
	int blake256_compress_sse2(uint32_t* h, int padding, uint64_t total, const uint8_t * datablock);
	int blake512_compress_sse2(uint64_t* h, uint64_t t0, int padding, const uint8_t* datablock);
	int blake512_compress_sse41(uint64_t* h, uint64_t t0, int padding, const uint8_t* datablock);
#ifdef _M_X64
	int blake256_compress_avxs(uint32_t* h, const uint8_t * datablock, uint64_t padding, uint32_t* total);
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

	inline uint32_t rotrblk(uint32_t x, int n)
	{
		return (x >> n) | (x << (32 - n));
	}

	void blake256::update(const uint8_t* data, size_t len)
	{
		while (pos + len >= 64)
		{
			memcpy(m + pos, data, 64 - pos);
			len -= 64 - pos;
			total += (64 - pos) * 8;
			transfunc(false);
			data += 64 - pos;
			pos = 0;
		}
		memcpy(m, data, len);
		pos += len;
		total += len * 8;
	}

	void blake256::init()
	{
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;
		s[0] = s[1] = s[2] = s[3] = 0;
		pos = 0;
		total = 0;
	};

	inline void G(int r, int i, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t* M) 
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

	inline void round(int r, uint32_t* M, uint32_t* v) 
	{
		G(r, 0, v[0], v[4], v[8], v[12], M);
		G(r, 1, v[1], v[5], v[9], v[13], M);
		G(r, 2, v[2], v[6], v[10], v[14], M);
		G(r, 3, v[3], v[7], v[11], v[15], M);
		G(r, 4, v[0], v[5], v[10], v[15], M);
		G(r, 5, v[1], v[6], v[11], v[12], M);
		G(r, 6, v[2], v[7], v[8], v[13], M);
		G(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	DEBUG
		printf("round %d v0 - v15: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}


	void blake256::transform(bool padding)
	{
		uint32_t M[16];
		for (uint32_t i = 0; i < 64 / 4; i++)
		{
			M[i] = _byteswap_ulong((reinterpret_cast<const uint32_t*>(m)[i]));
		}
#ifdef	DEBUG
		printf("M1 - M8: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint32_t t0 = static_cast<uint32_t>(total);
		uint32_t t1 = static_cast<uint32_t>((total) >> 32);
		if (padding)
			t0 = t1 = 0;


#ifdef	DEBUG
		printf("t0: %08X (%d), t1: %08X\n", t0, t0, t1);
#endif

		uint32_t v[16];
		for (int t = 0; t < 8; t++)
			v[t] = H[t];
		for (int t = 0; t < 4; t++)
			v[8 + t] = s[t] ^ c[t];
		v[12] = t0 ^ c[4];
		v[13] = t0 ^ c[5];
		v[14] = t1 ^ c[6];
		v[15] = t1 ^ c[7];

#ifdef	DEBUG
		printf("v0 - v15: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		for (int r = 0; r < 14; r++)
			round(r, M, v);

		for (int i = 0; i < 4; i++)
		{
			H[i] = H[i] ^ s[i] ^ v[i] ^ v[i + 8];
			H[i + 4] = H[i + 4] ^ s[i] ^ v[i + 4] ^ v[i + 8 + 4];
		}

#ifdef	DEBUG
		printf("H[0] - H[7]: %08X %08X %08X %08X %08X %08X %08X %08X\n",
			H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
#endif
	}

	void blake256::final(uint8_t* hash)
	{
		bool padding = !pos;
		m[pos++] = pos == 55 && hashbitlen() == 256 ? 0x81 : 0x80;
		if (pos > 56)
		{
			memset(m + pos, 0, 64 - pos);
			transfunc(false);
			pos = 0;
			padding = true;
		}
		if (pos < 56)
		{
			memset(m + pos, 0, 55 - pos);
			m[55] = hashbitlen() == 256 ? 0x01 : 0x00;
		}
		uint64_t mlen = _byteswap_uint64(total);
		memcpy(m + (64 - 8), &mlen, 64 / 8);
		transfunc(padding);
		for (int i = 0; i < 8; i++)
		{
			H[i] = _byteswap_ulong(H[i]);
		}
		memcpy(hash, H, hashbitlen()/8);
	}


	void blake512::update(const uint8_t* data, size_t len)
	{
		while (pos + len >= 128)
		{
			memcpy(m + pos, data, 128 - pos);
			len -= 128 - pos;
			total += (128 - pos) * 8;
			transfunc(false);
			data += 128 - pos;
			pos = 0;
		}
		memcpy(m, data, len);
		pos += len;
		total += len * 8;
	}


	static const uint64_t c512[16] = {
		0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
		0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
		0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
		0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69
	};

	void blake512::init()
	{
		H[0] = 0x6A09E667F3BCC908;
		H[1] = 0xBB67AE8584CAA73B;
		H[2] = 0x3C6EF372FE94F82B;
		H[3] = 0xA54FF53A5F1D36F1;
		H[4] = 0x510E527FADE682D1;
		H[5] = 0x9B05688C2B3E6C1F;
		H[6] = 0x1F83D9ABFB41BD6B;
		H[7] = 0x5BE0CD19137E2179;
		s[0] = s[1] = s[2] = s[3] = 0ULL;
		pos = 0;
		total = 0;
	};

	inline void G512(int r, int i, uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t* M) 
	{
		a = a + b + (M[S[r % 10][2 * i]] ^ (c512)[S[r % 10][2 * i + 1]]);
		d = _rotr64(d ^ a, 32);
		c = c + d;
		b = _rotr64(b ^ c, 25);
		a = a + b + (M[S[r % 10][2 * i + 1]] ^ (c512)[S[r % 10][2 * i]]);
		d = _rotr64(d ^ a, 16);
		c = c + d;
		b = _rotr64(b ^ c, 11);
	}

	inline void round512(int r, uint64_t* M, uint64_t* v) 
	{
		G512(r, 0, v[0], v[4], v[8], v[12], M);
		G512(r, 1, v[1], v[5], v[9], v[13], M);
		G512(r, 2, v[2], v[6], v[10], v[14], M);
		G512(r, 3, v[3], v[7], v[11], v[15], M);
		G512(r, 4, v[0], v[5], v[10], v[15], M);
		G512(r, 5, v[1], v[6], v[11], v[12], M);
		G512(r, 6, v[2], v[7], v[8], v[13], M);
		G512(r, 7, v[3], v[4], v[9], v[14], M);

#ifdef	DEBUG
		printf("round %d v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			r, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

	}

	void blake512::transform(bool padding)
	{
		uint64_t M[16];
		for (uint32_t i = 0; i < 128 / 8; i++)
		{
			M[i] = _byteswap_uint64((reinterpret_cast<const uint64_t*>(m)[i]));
		}
#ifdef	DEBUG
		printf("M1 - M8: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			M[0], M[1], M[2], M[3], M[4], M[5], M[6], M[7], M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);
#endif

		uint64_t t0 = total;
		uint64_t t1 = 0ULL;
		if (padding)
			t0 = t1 = 0;

#ifdef	DEBUG
		printf("t0: %016llx (%d), t1: %016llx\n", t0, t0, t1);
#endif

		uint64_t v[16];
		for (int t = 0; t < 8; t++)
			v[t] = H[t];
		for (int t = 0; t < 4; t++)
			v[8 + t] = s[t] ^ c512[t];
		v[12] = t0 ^ c512[4];
		v[13] = t0 ^ c512[5];
		v[14] = t1 ^ c512[6];
		v[15] = t1 ^ c512[7];

#ifdef	DEBUG
		printf("v0 - v15: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
#endif

		for (int r = 0; r < 16; r++)
			round512(r, M, v);

		for (int i = 0; i < 4; i++)
		{
			H[i] = H[i] ^ s[i] ^ v[i] ^ v[i + 8];
			H[i + 4] = H[i + 4] ^ s[i] ^ v[i + 4] ^ v[i + 8 + 4];
		}

#ifdef	DEBUG
		printf("H[0] - H[7]: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
#endif
	}

	void blake512::final(uint8_t* hash)
	{
		bool padding = !pos;
		m[pos++] = pos == 111 && hashbitlen() == 512 ? 0x81 : 0x80;
		if (pos > 112)
		{
			memset(m + pos, 0, 128 - pos);
			transfunc(false);
			pos = 0;
			padding = true;
		}
		if (pos < 112)
		{
			memset(m + pos, 0, 111 - pos);
			m[111] = hashbitlen() == 512 ? 0x01 : 0x00;
		}
		uint64_t mlen = _byteswap_uint64(total);
		memset(m + (128 - 16), 0, sizeof(uint64_t));
		memcpy(m + (128 - 8), &mlen, sizeof(uint64_t));
		transfunc(padding);
		for (int i = 0; i < 8; i++)
		{
			H[i] = _byteswap_uint64(H[i]);
		}
		memcpy(hash, H, hashbitlen()/8);
	}


	void blake384::init()
	{
		H[0] = 0xcbbb9d5dc1059ed8;
		H[1] = 0x629a292a367cd507;
		H[2] = 0x9159015a3070dd17;
		H[3] = 0x152fecd8f70e5939;
		H[4] = 0x67332667ffc00b31;
		H[5] = 0x8eb44a8768581511;
		H[6] = 0xdb0c2e0d64f98fa7;
		H[7] = 0x47b5481dbefa4fa4;
		s[0] = s[1] = s[2] = s[3] = 0ULL;
		pos = 0;
		total = 0;
	};

	void blake224::init()
	{
		H[0] = 0xC1059ED8;
		H[1] = 0x367CD507;
		H[2] = 0x3070DD17;
		H[3] = 0xF70E5939;
		H[4] = 0xFFC00B31;
		H[5] = 0x68581511;
		H[6] = 0x64F98FA7;
		H[7] = 0xBEFA4FA4;
		s[0] = s[1] = s[2] = s[3] = 0;
		pos = 0;
		total = 0;
	};

	blake256::blake256()
	{
		H = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * 8, 64);
		m = (uint8_t*)_aligned_malloc(sizeof(uint8_t) * 64, 64);

#ifdef _M_X64
		if (cpu_info::avx())
			transfunc = [this](bool padding) {
			uint32_t t[2];
			if (!padding)
			{
				t[0] = static_cast<uint32_t>(total);
				t[1] = static_cast<uint32_t>((total) >> 32);
			}

			blake256_compress_avxs(H, m, padding, t); 
			};
		else
#endif
		if (cpu_info::sse41())
			transfunc = [this](bool padding) { blake256_compress_sse41(H, padding, total, m); };
		else if (cpu_info::sse2())
			transfunc = [this](bool padding) { blake256_compress_sse2(H, padding, total, m); };
		else
			transfunc = bind(&blake256::transform, this, std::placeholders::_1);
	}

	blake256::~blake256()
	{
		_aligned_free(H);
		_aligned_free(m);
	}


	blake512::blake512()
	{
		H = (uint64_t*)_aligned_malloc(sizeof(uint64_t) * 8, 64);
		m = (uint8_t*)_aligned_malloc(sizeof(uint8_t) * 128, 64);

			if (cpu_info::sse41())
				transfunc = [this](bool padding) { blake512_compress_sse41(H, total, padding, m); };
			else if (cpu_info::sse2())
				transfunc = [this](bool padding) { blake512_compress_sse2(H, total, padding, m); };
			else
				transfunc = bind(&blake512::transform, this, std::placeholders::_1);
	}

	blake512::~blake512()
	{
		_aligned_free(H);
		_aligned_free(m);
	}

}

