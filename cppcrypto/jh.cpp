/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "cpuinfo.h"
#include "portability.h"
#include "jh.h"
#include <memory.h>
//#define CPPCRYPTO_DEBUG
//#define NO_OPTIMIZED_VERSIONS

#ifdef _MSC_VER
#define inline __forceinline
#endif

namespace cppcrypto
{
	static const uint64_t C[] = {
		0x67f815dfa2ded572, 0x571523b70a15847b, 0xf6875a4d90d6ab81, 0x402bd1c3c54f9f4e, 0x9cfa455ce03a98ea, 0x9a99b26699d2c503, 0x8a53bbf2b4960266, 0x31a2db881a1456b5,
		0xdb0e199a5c5aa303, 0x1044c1870ab23f40, 0x1d959e848019051c, 0xdccde75eadeb336f, 0x416bbf029213ba10, 0xd027bbf7156578dc, 0x5078aa3739812c0a, 0xd3910041d2bf1a3f,
		0x907eccf60d5a2d42, 0xce97c0929c9f62dd, 0xac442bc70ba75c18, 0x23fcc663d665dfd1, 0x1ab8e09e036c6e97, 0xa8ec6c447e450521, 0xfa618e5dbb03f1ee, 0x97818394b29796fd,
		0x2f3003db37858e4a, 0x956a9ffb2d8d672a, 0x6c69b8f88173fe8a, 0x14427fc04672c78a, 0xc45ec7bd8f15f4c5, 0x80bb118fa76f4475, 0xbc88e4aeb775de52, 0xf4a3a6981e00b882,
		0x1563a3a9338ff48e, 0x89f9b7d524565faa, 0xfde05a7c20edf1b6, 0x362c42065ae9ca36, 0x3d98fe4e433529ce, 0xa74b9a7374f93a53, 0x86814e6f591ff5d0, 0x9f5ad8af81ad9d0e,
		0x6a6234ee670605a7, 0x2717b96ebe280b8b, 0x3f1080c626077447, 0x7b487ec66f7ea0e0, 0xc0a4f84aa50a550d, 0x9ef18e979fe7e391, 0xd48d605081727686, 0x62b0e5f3415a9e7e,
		0x7a205440ec1f9ffc, 0x84c9f4ce001ae4e3, 0xd895fa9df594d74f, 0xa554c324117e2e55, 0x286efebd2872df5b, 0xb2c4a50fe27ff578, 0x2ed349eeef7c8905, 0x7f5928eb85937e44,
		0x4a3124b337695f70, 0x65e4d61df128865e, 0xe720b95104771bc7, 0x8a87d423e843fe74, 0xf2947692a3e8297d, 0xc1d9309b097acbdd, 0xe01bdc5bfb301b1d, 0xbf829cf24f4924da,
		0xffbf70b431bae7a4, 0x48bcf8de0544320d, 0x39d3bb5332fcae3b, 0xa08b29e0c1c39f45, 0x0f09aef7fd05c9e5, 0x34f1904212347094, 0x95ed44e301b771a2, 0x4a982f4f368e3be9,
		0x15f66ca0631d4088, 0xffaf52874b44c147, 0x30c60ae2f14abb7e, 0xe68c6eccc5b67046, 0x00ca4fbd56a4d5a4, 0xae183ec84b849dda, 0xadd1643045ce5773, 0x67255c1468cea6e8,
		0x16e10ecbf28cdaa3, 0x9a99949a5806e933, 0x7b846fc220b2601f, 0x1885d1a07facced1, 0xd319dd8da15b5932, 0x46b4a5aac01c9a50, 0xba6b04e467633d9f, 0x7eee560bab19caf6,
		0x742128a9ea79b11f, 0xee51363b35f7bde9, 0x76d350755aac571d, 0x01707da3fec2463a, 0x42d8a498afc135f7, 0x79676b9e20eced78, 0xa8db3aea15638341, 0x832c83324d3bc3fa,
		0xf347271c1f3b40a7, 0x9a762db734f04059, 0xfd4f21d26c4e3ee7, 0xef5957dc398dfdb8, 0xdaeb492b490c9b8d, 0x0d70f36849d7a25b, 0x84558d7ad0ae3b7d, 0x658ef8e4f0e9a5f5,
		0x533b1036f4a2b8a0, 0x5aec3e759e07a80c, 0x4f88e85692946891, 0x4cbcbaf8555cb05b, 0x7b9487f3993bbbe3, 0x5d1c6b72d6f4da75, 0x6db334dc28acae64, 0x71db28b850a5346c,
		0x2a518d10f2e261f8, 0xfc75dd593364dbe3, 0xa23fce43f1bcac1c, 0xb043e8023cd1bb67, 0x75a12988ca5b0a33, 0x5c5316b44d19347f, 0x1e4d790ec3943b92, 0x3fafeeb6d7757479,
		0x21391abef7d4a8ea, 0x5127234c097ef45c, 0xd23c32ba5324a326, 0xadd5a66d4a17a344, 0x08c9f2afa63e1db5, 0x563c6b91983d5983, 0x4d608672a17cf84c, 0xf6c76e08cc3ee246,
		0x5e76bcb1b333982f, 0x2ae6c4efa566d62b, 0x36d4c1bee8b6f406, 0x6321efbc1582ee74, 0x69c953f40d4ec1fd, 0x26585806c45a7da7, 0x16fae0061614c17e, 0x3f9d63283daf907e,
		0x0cd29b00e3f2c9d2, 0x300cd4b730ceaa5f, 0x9832e0f216512a74, 0x9af8cee3d830eb0d, 0x9279f1b57b9ec54b, 0xd36886046ee651ff, 0x316796e6574d239b, 0x05750a17f3a6e6cc,
		0xce6c3213d98176b1, 0x62a205f88452173c, 0x47154778b3cb2bf4, 0x486a9323825446ff, 0x65655e4e0758df38, 0x8e5086fc897cfcf2, 0x86ca0bd0442e7031, 0x4e477830a20940f0,
		0x8338f7d139eea065, 0xbd3a2ce437e95ef7, 0x6ff8130126b29721, 0xe7de9fefd1ed44a3, 0xd992257615dfa08b, 0xbe42dc12f6f7853c, 0x7eb027ab7ceca7d8, 0xdea83eaada7d8d53,
		0xd86902bd93ce25aa, 0xf908731afd43f65a, 0xa5194a17daef5fc0, 0x6a21fd4c33664d97, 0x701541db3198b435, 0x9b54cdedbb0f1eea, 0x72409751a163d09a, 0xe26f4791bf9d75f6
	};

	jh::jh(size_t hashsize) : hs(hashsize)
	{
		validate_hash_size(hashsize, {224, 256, 384, 512});

#ifndef NO_OPTIMIZED_VERSIONS
		if (cpu_info::sse2())
		{
			impl_.create<detail::jh_impl_sse2>();
		}
#endif
	}

	jh::~jh()
	{
		clear();
	}

	void jh::init()
	{
		pos = 0;
		total = 0;
		if (impl_)
			return impl_->init(hashsize());

		switch(hs)
		{
			case 512:
				H[0] = 0x17aa003e964bd16f;
				H[1] = 0x43d5157a052e6a63;
				H[2] = 0x0bef970c8d5e228a;
				H[3] = 0x61c3b3f2591234e9;
				H[4] = 0x1e806f53c1a01d89;
				H[5] = 0x806d2bea6b05a92a;
				H[6] = 0xa6ba7520dbcc8e58;
				H[7] = 0xf73bf8ba763a0fa9;
				H[8] = 0x694ae34105e66901;
				H[9] = 0x5ae66f2e8e8ab546;
				H[10] = 0x243c84c1d0a74710;
				H[11] = 0x99c15a2db1716e3b;
				H[12] = 0x56f8b19decf657cf;
				H[13] = 0x56b116577c8806a7;
				H[14] = 0xfb1785e6dffcc2e3;
				H[15] = 0x4bdd8ccc78465a54;
				break;
			case 256:
				H[0] = 0xebd3202c41a398eb;
				H[1] = 0xc145b29c7bbecd92;
				H[2] = 0xfac7d4609151931c;
				H[3] = 0x038a507ed6820026;
				H[4] = 0x45b92677269e23a4;
				H[5] = 0x77941ad4481afbe0;
				H[6] = 0x7a176b0226abb5cd;
				H[7] = 0xa82fff0f4224f056;
				H[8] = 0x754d2e7f8996a371;
				H[9] = 0x62e27df70849141d;
				H[10] = 0x948f2476f7957627;
				H[11] = 0x6c29804757b6d587;
				H[12] = 0x6c0d8eac2d275e5c;
				H[13] = 0x0f7a0557c6508451;
				H[14] = 0xea12247067d3e47b;
				H[15] = 0x69d71cd313abe389;
				break;
			case 384:
				H[0] = 0x8a3913d8c63b1e48;
				H[1] = 0x9b87de4a895e3b6d;
				H[2] = 0x2ead80d468eafa63;
				H[3] = 0x67820f4821cb2c33;
				H[4] = 0x28b982904dc8ae98;
				H[5] = 0x4942114130ea55d4;
				H[6] = 0xec474892b255f536;
				H[7] = 0xe13cf4ba930a25c7;
				H[8] = 0x4c45db278a7f9b56;
				H[9] = 0x0eaf976349bdfc9e;
				H[10] = 0xcd80aa267dc29f58;
				H[11] = 0xda2eeb9d8c8bc080;
				H[12] = 0x3a37d5f8e881798a;
				H[13] = 0x717ad1ddad6739f4;
				H[14] = 0x94d375a4bdd3b4a9;
				H[15] = 0x7f734298ba3f6c97;
				break;
			case 224:
				H[0] = 0xac989af962ddfe2d;
				H[1] = 0xe734d619d6ac7cae;
				H[2] = 0x161230bc051083a4;
				H[3] = 0x941466c9c63860b8;
				H[4] = 0x6f7080259f89d966;
				H[5] = 0xdc1a9b1d1ba39ece;
				H[6] = 0x106e367b5f32e811;
				H[7] = 0xc106fa027f8594f9;
				H[8] = 0xb340c8d85c1b4f1b;
				H[9] = 0x9980736e7fa1f697;
				H[10] = 0xd3a3eaada593dfdc;
				H[11] = 0x689a53c9dee831a4;
				H[12] = 0xe4a186ec8aa9b422;
				H[13] = 0xf06ce59c95ac74d5;
				H[14] = 0xbf2babb5ea0d9615;
				H[15] = 0x6eea64ddf0dc1196;
				break;
			default:
				memset(H.get(), 0, H.bytes());
				H[0] = swap_uint16(static_cast<uint16_t>(hs));

				unsigned char msg[64];
				memset(msg, 0, sizeof(msg));
				transform(msg, 1);
				break;
		}
	}

	void jh::update(const unsigned char* data, size_t len)
	{
		if (pos && pos + len >= 64)
		{
			memcpy(&m[0] + pos, data, 64 - pos);
			transform(&m[0], 1);
			len -= 64 - pos;
			total += (64 - pos) * 8;
			data += 64 - pos;
			pos = 0;
		}
		if (len >= 64)
		{
			size_t blocks = len / 64;
			size_t bytes = blocks * 64;
			transform((void*)(data), blocks);
			len -= bytes;
			total += (bytes)* 8;
			data += bytes;
		}
		memcpy(&m[0] + pos, data, len);
		pos += len;
		total += len * 8;
	}

	void jh::final(unsigned char* hash)
	{
		m[pos++] = 0x80;
		if (pos > 1)
		{
			memset(&m[0] + pos, 0, 64 - pos);
			transform(&m[0], 1);
			pos = 0;
		}
		memset(&m[0] + pos, 0, 56 - pos);
		uint64_t mlen = swap_uint64(total);
		memcpy(&m[0] + (64 - 8), &mlen, 64 / 8);
		transform(&m[0], 1);

		if (impl_)
			return impl_->output(hash, hashsize());

		memcpy(hash, ((unsigned char*)H.get()) + 128 - hashsize() / 8, hashsize() / 8);
	}

	static inline void bitswap(uint64_t& x, const uint64_t mask, int shift)
	{
		x = ((x & mask) << shift) | ((x & ~mask) >> shift);
	}

	static inline void bitswap(uint64_t* H, const uint64_t mask, int shift)
	{
		bitswap(H[2], mask, shift);
		bitswap(H[3], mask, shift);
		bitswap(H[6], mask, shift);
		bitswap(H[7], mask, shift);
		bitswap(H[10], mask, shift);
		bitswap(H[11], mask, shift);
		bitswap(H[14], mask, shift);
		bitswap(H[15], mask, shift);
	}

	static inline void Sbitsli(uint64_t& x0a, uint64_t& x0b, uint64_t& x1a, uint64_t& x1b, uint64_t& x2a, uint64_t& x2b, uint64_t& x3a, uint64_t& x3b, const uint64_t ca, const uint64_t cb)
	{
		x3a = ~x3a;
		x3b = ~x3b;
		x0a ^= (ca & ~x2a);
		x0b ^= (cb & ~x2b);
		uint64_t ta = ca ^ (x0a & x1a);
		uint64_t tb = cb ^ (x0b & x1b);
		x0a ^= (x2a & x3a);
		x0b ^= (x2b & x3b);
		x3a ^= (~x1a & x2a);
		x3b ^= (~x1b & x2b);
		x1a ^= (x0a & x2a);
		x1b ^= (x0b & x2b);
		x2a ^= (x0a & ~x3a);
		x2b ^= (x0b & ~x3b);
		x0a ^= (x1a | x3a);
		x0b ^= (x1b | x3b);
		x3a ^= (x1a & x2a);
		x3b ^= (x1b & x2b);
		x1a ^= (ta & x0a);
		x1b ^= (tb & x0b);
		x2a ^= ta;
		x2b ^= tb;
	}

	static inline void Lbitsli(uint64_t* H)
	{
		H[2] ^= H[4];
		H[3] ^= H[5];
		H[6] ^= H[8];
		H[7] ^= H[9];
		H[10] ^= H[12] ^ H[0];
		H[11] ^= H[13] ^ H[1];
		H[14] ^= H[0];
		H[15] ^= H[1];
		H[0] ^= H[6];
		H[1] ^= H[7];
		H[4] ^= H[10];
		H[5] ^= H[11];
		H[8] ^= H[14] ^ H[2];
		H[9] ^= H[15] ^ H[3];
		H[12] ^= H[2];
		H[13] ^= H[3];
	}

	void jh::transform(void* mp, uint64_t num_blks)
	{
		for (uint64_t blk = 0; blk < num_blks; blk++)
		{
			if (impl_)
			{
				impl_->F8(((const unsigned char*)mp) + blk * 64);
				continue;
			}
			const uint64_t* M = (const uint64_t*)(((const unsigned char*)mp) + blk * 64);
			H[0] ^= M[0];
			H[1] ^= M[1];
			H[2] ^= M[2];
			H[3] ^= M[3];
			H[4] ^= M[4];
			H[5] ^= M[5];
			H[6] ^= M[6];
			H[7] ^= M[7];


#ifdef CPPCRYPTO_DEBUG
			printf("xor:\n");
			for (int i = 0; i < 16; i++)
				printf("H[%d] = %016I64x\n", i, H[i]);
			printf("\n");
#endif


			// partially unroll
			for (int r = 0; r < 42; r += 7)
			{
				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[r * 4 + 0], C[r * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[r * 4 + 2], C[r * 4 + 3]);

#ifdef CPPCRYPTO_DEBUG
				printf("round %d SS:\n", r);
				for (int i = 0; i < 16; i++)
					printf("H[%d] = %016I64x\n", i, H[i]);
				printf("\n");
#endif

				Lbitsli(H);

#ifdef CPPCRYPTO_DEBUG
				printf("round %d L:\n", r);
				for (int i = 0; i < 16; i++)
					printf("H[%d] = %016I64x\n", i, H[i]);
				printf("\n");
#endif

				bitswap(H, 0x5555555555555555ULL, 1);

#ifdef CPPCRYPTO_DEBUG
				printf("round %d swap:\n", r);
				for (int i = 0; i < 16; i++)
					printf("H[%d] = %016I64x\n", i, H[i]);
				printf("\n");
#endif

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 1) * 4 + 0], C[(r + 1) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 1) * 4 + 2], C[(r + 1) * 4 + 3]);
				Lbitsli(H);
				bitswap(H, 0x3333333333333333ULL, 2);

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 2) * 4 + 0], C[(r + 2) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 2) * 4 + 2], C[(r + 2) * 4 + 3]);
				Lbitsli(H);
				bitswap(H, 0x0f0f0f0f0f0f0f0fULL, 4);

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 3) * 4 + 0], C[(r + 3) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 3) * 4 + 2], C[(r + 3) * 4 + 3]);
				Lbitsli(H);
				bitswap(H, 0x00ff00ff00ff00ffULL, 8);

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 4) * 4 + 0], C[(r + 4) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 4) * 4 + 2], C[(r + 4) * 4 + 3]);
				Lbitsli(H);
				bitswap(H, 0x0000ffff0000ffffULL, 16);

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 5) * 4 + 0], C[(r + 5) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 5) * 4 + 2], C[(r + 5) * 4 + 3]);
				Lbitsli(H);
				bitswap(H, 0x00000000ffffffffULL, 32);

				Sbitsli(H[0], H[1], H[4], H[5], H[8], H[9], H[12], H[13], C[(r + 6) * 4 + 0], C[(r + 6) * 4 + 1]);
				Sbitsli(H[2], H[3], H[6], H[7], H[10], H[11], H[14], H[15], C[(r + 6) * 4 + 2], C[(r + 6) * 4 + 3]);
				Lbitsli(H);
				std::swap(H[2], H[3]);
				std::swap(H[6], H[7]);
				std::swap(H[10], H[11]);
				std::swap(H[14], H[15]);
			}

			H[8] ^= M[0];
			H[9] ^= M[1];
			H[10] ^= M[2];
			H[11] ^= M[3];
			H[12] ^= M[4];
			H[13] ^= M[5];
			H[14] ^= M[6];
			H[15] ^= M[7];
		}
	}

	void jh::clear()
	{
		zero_memory(H.get(), H.bytes());
		zero_memory(m.data(), m.size() * sizeof(m[0]));
	}

}
