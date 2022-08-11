/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "portability.h"
#include "esch.h"
#include <memory.h>

//#define NO_OPTIMIZED_VERSIONS

namespace cppcrypto
{

static const uint32_t C[8] = {
	0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738, 0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d
};

static inline void sparkle(std::array<uint32_t, 16>& H, int rounds, int ns)
{
	for(int s = 0; s < ns; s++) 
	{
		H[1] ^= C[s % 8];
		H[3] ^= s;
		for (int j = 0, px = 0, py = 1; j < rounds; j++, px += 2, py += 2)
		{
			H[px] += rotater32(H[py], 31);
			H[py] ^= rotater32(H[px], 24);
			H[px] ^= C[j];
			H[px] += rotater32(H[py], 17);
			H[py] ^= rotater32(H[px], 17);
			H[px] ^= C[j];
			H[px] += H[py];
			H[py] ^= rotater32(H[px], 31);
			H[px] ^= C[j];
			H[px] += rotater32(H[py], 24);
			H[py] ^= rotater32(H[px], 16);
			H[px] ^= C[j];
		}
		uint32_t x = H[0] ^ H[2] ^ H[4];
		uint32_t y = H[1] ^ H[3] ^ H[5];
		if (rounds > 6)
		{
			x ^= H[6];
			y ^= H[7];
		}
		x = rotater32(x ^ (x << 16), 16);
		y = rotater32(y ^ (y << 16), 16);
		
		for (int i = 0, j = rounds; i < rounds; i+=2, j+=2)
		{
			H[j] ^= H[i] ^ y;
			H[j + 1] ^= H[i + 1] ^ x;
		}
		x = H[rounds];
		y = H[rounds + 1];
		for (int i = 0; i < rounds - 2; i++)
		{
			H[i + rounds] = H[i];
			H[i] = H[i + rounds + 2];
		}
		H[rounds * 2 - 2] = H[rounds - 2];
		H[rounds * 2 - 1] = H[rounds - 1];
		H[rounds - 2] = x;
		H[rounds - 1] = y;
	}
}

void esch::init()
{
	pos = 0;
	total = 0;
	memset(H.data(), 0, sizeof(uint32_t)*16);
	if (impl_)
		impl_->init();
};

void esch::update(const unsigned char* data, size_t len)
{
	const size_t bss = 16;
	if (pos && pos + len > bss)
	{
		memcpy(m.data() + pos, data, bss - pos);
		transform(m.data(), 1, false);
		len -= bss - pos;
		data += bss - pos;
		total += bss * 8;
		pos = 0;
	}
	if (len > 16)
	{
		size_t blocks = (len - 1) / bss;
		size_t bytes = blocks * bss;
		transform(data, blocks, false);
		len -= bytes;
		data += bytes;
		total += (bytes)* 8;
	}
	memcpy(m.data() + pos, data, len);
	pos += len;
}

void esch::final(unsigned char* hash)
{
	if (impl_)
		return impl_->final(hash, m.data(), total, pos);

	size_t processed = 0;
	total = 1;
	if (pos < 16)
	{
		memset(&m[pos], 0, 16 - pos);
		m[pos] = 0x80;
		H[(hs+128)/64 - 1] ^= 0x1000000;
	}
	else
		H[(hs+128)/64 - 1] ^= 0x2000000;

	transform(m.data(), 1, true);

	size_t hss = hs / 8;
	while (processed < hss)
	{
		if (!total)
			sparkle(H, hs > 256 ? 8 : 6, hs > 256 ? 8 : 7);
		pos = std::min(hss - processed, static_cast<size_t>(16));
		memcpy(hash + processed, H.data(), pos);
		processed += pos;
		total = 0;
	}
}

void esch::transform(const unsigned char* data, size_t num_blks, bool lastBlock)
{
	if (impl_)
		return impl_->transform(data, num_blks, lastBlock);

	for (size_t blk = 0; blk < num_blks; blk++)
	{
		uint32_t M[4];
		for (int i = 0; i < 4; i++)
			M[i] = reinterpret_cast<const uint32_t*>(data)[blk * 4 + i];
		uint32_t x = M[0] ^ M[2];
		uint32_t y = M[1] ^ M[3];
		x = rotater32(x ^ (x << 16), 16);
		y = rotater32(y ^ (y << 16), 16);
		H[0] = H[0] ^ M[0] ^ y;
		H[1] = H[1] ^ M[1] ^ x;
		H[2] = H[2] ^ M[2] ^ y;
		H[3] = H[3] ^ M[3] ^ x;
		H[4] ^= y;
		H[5] ^= x;
		if (hs > 256)
		{
			H[6] ^= y;
			H[7] ^= x;
		}	
		int steps = lastBlock ? 11 : 7;
		if (hs > 256)
			steps++;
		sparkle(H, hs > 256 ? 8 : 6, steps);
	}
}

esch::~esch()
{
	clear();
}

esch::esch(size_t hashsize)
	: hs(hashsize), bs(128)
{
	validate_hash_size(hashsize, { 256, 384 });

#ifndef NO_OPTIMIZED_VERSIONS
	if (cpu_info::avx2())
	{
		if (hashsize > 256)
			impl_.create<detail::esch384_avx2_impl>();
		else
			impl_.create<detail::esch256_avx2_impl>();
	}
#endif

}

void esch::clear()
{
	zero_memory(H.data(), H.size() * sizeof(H[0]));
	zero_memory(m.data(), m.size() * sizeof(m[0]));
}

}

