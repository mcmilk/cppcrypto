/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "mars.h"
#include "portability.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <bitset>

#ifdef _MSC_VER
#define inline __forceinline
#endif

//#define CPPCRYPTO_DEBUG

namespace cppcrypto
{
	static const uint32_t S[512] = {
		0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93, 0x85d0582e, 0x2a4b5705,
		0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4, 0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83,
		0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac, 0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6,
		0x210a5f18, 0xc6986a26, 0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
		0x80f6e831, 0xab6f04ad, 0x56fb9b53, 0x8b2e095c, 0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253, 0xae136749, 0xe82aae86,
		0x93365104, 0x99404a66, 0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e, 0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b,
		0xc190c6e3, 0x07dfb846, 0x6eb88816, 0x2d0dcc4a, 0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45, 0xeafc8ca8, 0xdb1129d6,
		0xb0449e20, 0x0f5407fb, 0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958, 0xababa014, 0xb6ccd201, 0x38d6279f, 0x02682215,
		0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c, 0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c, 0xfae527e5, 0x36a1c330,
		0x3412e1ae, 0xf257f462, 0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44, 0x5ded0ab8, 0x75ce09c8, 0x9654f93e, 0x698c0cca,
		0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df, 0xfc5d6166, 0xe35f9288, 0xc079550d, 0x0591aee8, 0x8e531e74, 0x75fe3578,
		0x2f6d829a, 0xf60b21ae, 0x95e8eb8d, 0x6699486b, 0x901d7d9b, 0xfd6d6e31, 0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365,
		0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3, 0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55, 0x3afd7d3e, 0xd2f29e01,
		0x29a9d1f6, 0xefb10c53, 0xcf3b870f, 0xb414935c, 0x664465ed, 0x024acac7, 0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8,
		0x040a7a10, 0x6cd81807, 0x8a98be4c, 0xaccea063, 0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13, 0x386b2c4a, 0x52e8dd58,
		0x58656dfb, 0x50820371, 0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
		0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1, 0xa64fc9c6, 0xf6957d49,
		0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294, 0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7,
		0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98, 0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f, 0xb0a495f8, 0x614deed0,
		0xb5778eea, 0x5941792d, 0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550, 0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
		0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9, 0x07128dc0, 0x0d44db62,
		0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e, 0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3,
		0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52, 0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da,
		0xab394825, 0x9ad3048f, 0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
		0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca, 0x1a9a5f08, 0xfcd651b9,
		0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030, 0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69,
		0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734, 0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978, 0x73398d32,
		0x0f59573e, 0xe9df2b03, 0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
		0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568, 0x8894b022, 0x2f511c27,
		0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10, 0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce,
		0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047, 0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3,
		0x088f8ead, 0x07adf158, 0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
		0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05, 0x010e65c4, 0x86a3d963,
		0xf907b5a0, 0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33, 0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
		0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd, 0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f, 0xe2eb6dc2,
		0x97338b02, 0x06c9f246, 0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
		0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b, 0x108f8fa4, 0x10223eda,
		0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba, 0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c,
		0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5, 0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6,
		0xd7590f15, 0x4e03bb47, 0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
		0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6, 0x054356dc, 0xde7ced35,
		0xd51a138b, 0x62088cc9, 0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68, 0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2,
		0x72698d7d, 0x5e368c31, 0xf7d95e2e, 0xa1d3493f, 0xdcd9433e, 0x896f1552, 0x4bc4ca7a, 0xa6d1baf4, 0xa5a96dcc, 0x0bef8b46,
		0xa169fda7, 0x74df40b7, 0x4e208804, 0x9a756607, 0x038e87c8, 0x20211e44, 0x8b7ad4bf, 0xc6403f35, 0x1848e36d, 0x80bdb038,
		0x1e62891c, 0x643d2107, 0xbf04d6f8, 0x21092c8c, 0xf644f389, 0x0778404e, 0x7b78adb8, 0xa2c52d53, 0x42157abe, 0xa2253e2e,
		0x7bf3f4ae, 0x80f594f9, 0x953194e7, 0x77eb92ed, 0xb3816930, 0xda8d9336, 0xbf447469, 0xf26d9483, 0xee6faed5, 0x71371235,
		0xde425f73, 0xb4e59f43, 0x7dbe2d4e, 0x2d37b185, 0x49dc9a63, 0x98c39d98, 0x1301c9a2, 0x389b1bbf, 0x0c18588d, 0xa421c1ba,
		0x7aa3865c, 0x71e08558, 0x3c5cfcaa, 0x7d239ca4, 0x0297d9dd, 0xd7dc2830, 0x4b37802b, 0x7428ab54, 0xaeee0347, 0x4b3fbb85,
		0x692f2f08, 0x134e578e, 0x36d9e0bf, 0xae8b5fcf, 0xedb93ecf, 0x2b27248e, 0x170eb1ef, 0x7dc57fd6, 0x1e760f16, 0xb1136601,
		0x864e1b9b, 0xd7ea7319, 0x3ab871bd, 0xcfa4d76f, 0xe31bd782, 0x0dbeb469, 0xabb96061, 0x5370f85d, 0xffb07e37, 0xda30d0fb,
		0xebc977b6, 0x0b98b40f, 0x3a4d0fe6, 0xdf4fc26b, 0x159cf22a, 0xc298d6e2, 0x2b78ef6a, 0x61a94ac0, 0xab561187, 0x14eea0f0,
		0xdf0d4164, 0x19af70ee
	};

	static inline void E(uint32_t x, uint32_t k1, uint32_t k2, uint32_t& o1, uint32_t& o2, uint32_t& o3)
	{
		uint32_t R = rotatel32(x, 13);
		uint32_t M = x + k1;
		uint32_t L = S[M & 0x1FF];
		R *= k2;
		R = rotatel32(R, 5);
		L ^= R;
		M = rotatel32(M, R & 0x1F);
		R = rotatel32(R, 5);
		L ^= R;
		L = rotatel32(L, R & 0x1F);
		o1 = L;
		o2 = M;
		o3 = R;
	}

	static inline uint32_t gen_mask(uint32_t w)
	{
		uint32_t M = 0;

		for (int k = 0; k < 23; k++)
		{
			uint32_t x = w >> k;
			uint32_t t = x & 0x3FF;
			if (!t || t == 0x3FF)
				M |= 0x3FF << k;
		}
		M &= ((~w ^ (w << 1)) & (~w ^ (w >> 1))) & 0x7FFFFFFC;
		return M;
	}

	static inline bool do_init(uint32_t* T, uint32_t* rk)
	{
		for (int j = 0; j < 4; j++)
		{
			for (int i = 0; i < 15; i++)
				T[i] = T[i] ^ rotatel32(T[(i + 15 - 7) % 15] ^ T[(i + 15 - 2) % 15], 3) ^ (4 * i + j);

			for (int k = 0; k < 4; k++)
			{
				for (int i = 0; i < 15; i++)
					T[i] = rotatel32(T[i] + S[T[(i + 15 - 1) % 15] & 0x1FF], 9);
			}

			for (int i = 0; i < 10; i++)
				rk[10 * j + i] = T[4 * i % 15];
		}

		for (int i = 5; i <= 35; i += 2)
		{
			uint32_t j = rk[i] & 3, w = rk[i] | 3;
			uint32_t M = gen_mask(w);

			if (M)
			{
				uint32_t p = rotatel32(S[265 + j], rk[i - 1] & 0x0000001F);
				rk[i] = w ^ (p & M);
			}
			else
				rk[i] = w;
		}

#ifdef CPPCRYPTO_DEBUG
		for(int i = 0; i < 40; i++)
			printf("rk[%d] = %08x\n", i, rk[i]);
#endif

		return true;
	}

	static inline void forward_mix(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3)
	{
		x1 = (x1 ^ S[uint8_t(x0)]) + S[256 + uint8_t(x0 >> 8)];
		x2 += S[uint8_t(x0 >> 16)];
		x3 ^= S[256 + uint8_t(x0 >> 24)];
		x0 = rotater32(x0, 24);
		if (i == 0 || i == 4)
			x0 = x0 + x3;
		else if (i == 1 || i == 5)
			x0 = x0 + x1;
	}

	static inline void keyed_transform_a(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t* rk)
	{
		uint32_t o1, o2, o3;
		E(x0, rk[2 * i + 4], rk[2 * i + 5], o1, o2, o3);
		x0 = rotatel32(x0, 13);
		x2 += o2;
		x1 += o1;
		x3 ^= o3;
	}

	static inline void keyed_transform_b(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t* rk)
	{
		uint32_t o1, o2, o3;
		E(x0, rk[2 * i + 4], rk[2 * i + 5], o1, o2, o3);
		x0 = rotatel32(x0, 13);
		x2 += o2;
		x3 += o1;
		x1 ^= o3;
	}

	static inline void keyed_transform_a_decr(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t* rk)
	{
		uint32_t o1, o2, o3;
		x0 = rotater32(x0, 13);
		E(x0, rk[2 * i + 4], rk[2 * i + 5], o1, o2, o3);
		x2 -= o2;
		x1 -= o1;
		x3 ^= o3;
	}

	static inline void keyed_transform_b_decr(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3, uint32_t* rk)
	{
		uint32_t o1, o2, o3;
		x0 = rotater32(x0, 13);
		E(x0, rk[2 * i + 4], rk[2 * i + 5], o1, o2, o3);
		x2 -= o2;
		x3 -= o1;
		x1 ^= o3;
	}

	static inline void backwards_mix(int i, uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3)
	{
		if (i == 2 || i == 6)
			x0 = x0 - x3;
		else if (i == 3 || i == 7)
			x0 = x0 - x1;
		x1 = x1 ^ S[256 + uint8_t(x0)];
		x2 = x2 - S[uint8_t(x0 >> 24)];
		x3 = (x3 - S[256 + uint8_t(x0 >> 16)]) ^ S[uint8_t(x0 >> 8)];
		x0 = rotatel32(x0, 24);
	}

	namespace detail
	{
		void mars::clear()
		{
			memset(rk, 0, sizeof(rk));
		}

		void mars::encrypt_block(const uint8_t* in, uint8_t* out)
		{
			uint32_t x0, x1, x2, x3;
			x0 = *(((const uint32_t*)in) + 0) + rk[0];
			x1 = *(((const uint32_t*)in) + 1) + rk[1];
			x2 = *(((const uint32_t*)in) + 2) + rk[2];
			x3 = *(((const uint32_t*)in) + 3) + rk[3];

			forward_mix(0, x0, x1, x2, x3);
			forward_mix(1, x1, x2, x3, x0);
			forward_mix(2, x2, x3, x0, x1);
			forward_mix(3, x3, x0, x1, x2);
			forward_mix(4, x0, x1, x2, x3);
			forward_mix(5, x1, x2, x3, x0);
			forward_mix(6, x2, x3, x0, x1);
			forward_mix(7, x3, x0, x1, x2);

#ifdef CPPCRYPTO_DEBUG
			printf("fwdmix: %08x %08x %08x %08x\n", x0, x1, x2, x3);
#endif

			keyed_transform_a(0, x0, x1, x2, x3, rk);
			keyed_transform_a(1, x1, x2, x3, x0, rk);
			keyed_transform_a(2, x2, x3, x0, x1, rk);
			keyed_transform_a(3, x3, x0, x1, x2, rk);
			keyed_transform_a(4, x0, x1, x2, x3, rk);
			keyed_transform_a(5, x1, x2, x3, x0, rk);
			keyed_transform_a(6, x2, x3, x0, x1, rk);
			keyed_transform_a(7, x3, x0, x1, x2, rk);
			keyed_transform_b(8, x0, x1, x2, x3, rk);
			keyed_transform_b(9, x1, x2, x3, x0, rk);
			keyed_transform_b(10, x2, x3, x0, x1, rk);
			keyed_transform_b(11, x3, x0, x1, x2, rk);
			keyed_transform_b(12, x0, x1, x2, x3, rk);
			keyed_transform_b(13, x1, x2, x3, x0, rk);
			keyed_transform_b(14, x2, x3, x0, x1, rk);
			keyed_transform_b(15, x3, x0, x1, x2, rk);

#ifdef CPPCRYPTO_DEBUG
			printf("keyed-transform: %08x %08x %08x %08x\n", x0, x1, x2, x3);
#endif

			backwards_mix(0, x0, x1, x2, x3);
			backwards_mix(1, x1, x2, x3, x0);
			backwards_mix(2, x2, x3, x0, x1);
			backwards_mix(3, x3, x0, x1, x2);
			backwards_mix(4, x0, x1, x2, x3);
			backwards_mix(5, x1, x2, x3, x0);
			backwards_mix(6, x2, x3, x0, x1);
			backwards_mix(7, x3, x0, x1, x2);

			*(((uint32_t*)out) + 0) = x0 - rk[36];
			*(((uint32_t*)out) + 1) = x1 - rk[37];
			*(((uint32_t*)out) + 2) = x2 - rk[38];
			*(((uint32_t*)out) + 3) = x3 - rk[39];
		}

		void mars::decrypt_block(const uint8_t* in, uint8_t* out)
		{
			uint32_t x0, x1, x2, x3;
			x0 = *(((const uint32_t*)in) + 0) + rk[36];
			x1 = *(((const uint32_t*)in) + 1) + rk[37];
			x2 = *(((const uint32_t*)in) + 2) + rk[38];
			x3 = *(((const uint32_t*)in) + 3) + rk[39];

			forward_mix(0, x3, x2, x1, x0);
			forward_mix(1, x2, x1, x0, x3);
			forward_mix(2, x1, x0, x3, x2);
			forward_mix(3, x0, x3, x2, x1);
			forward_mix(4, x3, x2, x1, x0);
			forward_mix(5, x2, x1, x0, x3);
			forward_mix(6, x1, x0, x3, x2);
			forward_mix(7, x0, x3, x2, x1);

#ifdef CPPCRYPTO_DEBUG
			printf("fwdmix-decr: %08x %08x %08x %08x\n", x0, x1, x2, x3);
#endif
			keyed_transform_a_decr(15, x3, x2, x1, x0, rk);
			keyed_transform_a_decr(14, x2, x1, x0, x3, rk);
			keyed_transform_a_decr(13, x1, x0, x3, x2, rk);
			keyed_transform_a_decr(12, x0, x3, x2, x1, rk);
			keyed_transform_a_decr(11, x3, x2, x1, x0, rk);
			keyed_transform_a_decr(10, x2, x1, x0, x3, rk);
			keyed_transform_a_decr(9, x1, x0, x3, x2, rk);
			keyed_transform_a_decr(8, x0, x3, x2, x1, rk);
			keyed_transform_b_decr(7, x3, x2, x1, x0, rk);
			keyed_transform_b_decr(6, x2, x1, x0, x3, rk);
			keyed_transform_b_decr(5, x1, x0, x3, x2, rk);
			keyed_transform_b_decr(4, x0, x3, x2, x1, rk);
			keyed_transform_b_decr(3, x3, x2, x1, x0, rk);
			keyed_transform_b_decr(2, x2, x1, x0, x3, rk);
			keyed_transform_b_decr(1, x1, x0, x3, x2, rk);
			keyed_transform_b_decr(0, x0, x3, x2, x1, rk);

#ifdef CPPCRYPTO_DEBUG
			printf("keyed-transform-decr: %08x %08x %08x %08x\n", x0, x1, x2, x3);
#endif

			backwards_mix(0, x3, x2, x1, x0);
			backwards_mix(1, x2, x1, x0, x3);
			backwards_mix(2, x1, x0, x3, x2);
			backwards_mix(3, x0, x3, x2, x1);
			backwards_mix(4, x3, x2, x1, x0);
			backwards_mix(5, x2, x1, x0, x3);
			backwards_mix(6, x1, x0, x3, x2);
			backwards_mix(7, x0, x3, x2, x1);

			*(((uint32_t*)out) + 0) = x0 - rk[0];
			*(((uint32_t*)out) + 1) = x1 - rk[1];
			*(((uint32_t*)out) + 2) = x2 - rk[2];
			*(((uint32_t*)out) + 3) = x3 - rk[3];
		}
	}

	bool mars448::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 448 / 8);
		T[14] = 448 / 32;
		return do_init(T, rk);
	}

	bool mars192::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 192 / 8);
		T[6] = 192 / 32;
		memset(T + 7, 0, 8 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars256::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 256 / 8);
		T[8] = 256 / 32;
		memset(T + 9, 0, 6 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars320::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 320 / 8);
		T[10] = 320 / 32;
		memset(T + 11, 0, 4 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars128::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 128 / 8);
		T[4] = 128 / 32;
		memset(T + 5, 0, 10 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars160::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 160 / 8);
		T[5] = 160 / 32;
		memset(T + 6, 0, 9 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars224::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 224 / 8);
		T[7] = 224 / 32;
		memset(T + 8, 0, 7 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars288::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 288 / 8);
		T[9] = 288 / 32;
		memset(T + 10, 0, 5 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars352::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 352 / 8);
		T[11] = 352 / 32;
		memset(T + 12, 0, 3 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars384::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 384 / 8);
		T[12] = 384 / 32;
		memset(T + 13, 0, 2 * 32 / 8);
		return do_init(T, rk);
	}

	bool mars416::init(const uint8_t* key, block_cipher::direction direction)
	{
		uint32_t T[15];
		memcpy(&T, key, 416 / 8);
		T[13] = 416 / 32;
		memset(T + 14, 0, 1 * 32 / 8);
		return do_init(T, rk);
	}
}
