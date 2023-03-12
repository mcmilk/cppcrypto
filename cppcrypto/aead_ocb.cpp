/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aead_ocb.h"
#include "functions.h"
#include "portability.h"
#include "random_bytes.h"
#include <stdexcept>
#include <string.h>
//#define NO_OPTIMIZED_VERSIONS
#ifndef NO_OPTIMIZED_VERSIONS
#include "cpuinfo.h"
#endif

#include <tmmintrin.h>

namespace cppcrypto
{
namespace
{
	template<size_t BS>
	struct ocb_constants
	{
	};

	template<>
	struct ocb_constants<128>
	{
		static const uint32_t residue = 135;
		static const size_t shift = 8;
		static const size_t tagrep = 7;
		static const uint16_t bottom_mask = 0x3F00;
		static const uint16_t zero_nonce_mask = 0xC0FF;
		static const size_t max_iv_bytes = 15;
	};

	template<>
	struct ocb_constants<160>
	{
		static const uint32_t residue = 45;
		static const size_t shift = 24;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0x7F00;
		static const uint16_t zero_nonce_mask = 0x80FF;
		static const size_t max_iv_bytes = 18;
	};

	template<>
	struct ocb_constants<192>
	{
		static const uint32_t residue = 135;
		static const size_t shift = 40;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0x7F00;
		static const uint16_t zero_nonce_mask = 0x80FF;
		static const size_t max_iv_bytes = 22;
	};

	template<>
	struct ocb_constants<224>
	{
		static const uint32_t residue = 777;
		static const size_t shift = 80;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0x7F00;
		static const uint16_t zero_nonce_mask = 0x80FF;
		static const size_t max_iv_bytes = 26;
	};

	template<>
	struct ocb_constants<256>
	{
		static const uint32_t residue = 1061;
		static const size_t shift = 1;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0xFF00;
		static const uint16_t zero_nonce_mask = 0x00FF;
		static const size_t max_iv_bytes = 30;
	};

	template<>
	struct ocb_constants<512>
	{
		static const uint32_t residue = 293;
		static const size_t shift = 176;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0xFF00;
		static const uint16_t zero_nonce_mask = 0x00FF;
		static const size_t max_iv_bytes = 62;
	};

	template<>
	struct ocb_constants<1024>
	{
		static const uint32_t residue = 524355;
		static const size_t shift = 352;
		static const size_t tagrep = 8;
		static const uint16_t bottom_mask = 0xFF01;
		static const uint16_t zero_nonce_mask = 0x00FE;
		static const size_t max_iv_bytes = 126;
	};

	template<typename T, size_t N>
	struct ocbnonsse
	{
		T a[N];

		static const size_t block_bytes = sizeof(a);
		static const size_t block_bits = sizeof(a) * 8;

		static inline ocbnonsse zero() { ocbnonsse<T, N> t; memset(&t, 0, sizeof(t)); return t; }

		inline ocbnonsse& operator ^=(const ocbnonsse& other)
		{
			for (size_t i = 0; i < N; i++)
				a[i] ^= other.a[i];
			return *this;
		}

		inline ocbnonsse& operator |=(const ocbnonsse& other)
		{
			for (size_t i = 0; i < N; i++)
				a[i] |= other.a[i];
			return *this;
		}

		inline void unload(unsigned char* out) const
		{
			memcpy(out, this, block_bytes);
		}

		inline void unload_partial(unsigned char* out, size_t bytes) const
		{
			memcpy(out, this, bytes);
		}

		static inline ocbnonsse load(const unsigned char* in)
		{
			ocbnonsse<T, N> t;
			memcpy(t.a, in, block_bytes);
			return t;
		}

		static inline ocbnonsse load_partial(const unsigned char* in, size_t bytes)
		{
			ocbnonsse<T, N> t = zero();
			memcpy(t.a, in, bytes);
			return t;
		}

		static inline ocbnonsse load_partial_with_padding(const unsigned char* in, size_t bytes)
		{
			ocbnonsse<T, N> t = zero();
			memcpy(t.a, in, bytes);
			reinterpret_cast<unsigned char*>(t.a)[bytes] = 0x80;
			return t;
		}

		inline void pad(size_t remaining)
		{
			memset(reinterpret_cast<unsigned char*>(a) + remaining, 0, block_bytes - remaining);
			reinterpret_cast<unsigned char*>(a)[remaining] = 0x80;
		}

		inline ocbnonsse double_block() const
		{
			T ta[N];
			for (size_t i = 0; i < N; i++)
				ta[i] = cppcrypto::byteswap(a[i]);

			ocbnonsse<T, N> t = zero();
			for (size_t i = 0; i < N - 1; i++)
				t.a[i] = cppcrypto::byteswap((ta[i] << 1) | (ta[i + 1] >> (sizeof(T)*8 - 1)));

			t.a[N-1] = cppcrypto::byteswap((ta[N - 1] << 1) ^ ((static_cast<typename std::make_signed<T>::type>(ta[0]) >> (sizeof(T) * 8 - 1)) & ocb_constants<block_bits>::residue));

			return t;
		}

		inline ocbnonsse shift_right(size_t bits) const
		{
			T ta[N];
			for (size_t i = 0; i < N; i++)
				ta[i] = cppcrypto::byteswap(a[i]);

			for (size_t b = bits, k = 0; b >= sizeof(T) * 8; b -= sizeof(T) * 8, k++)
			{
				for (size_t i = N - 1; i > k; i--)
					ta[i] = ta[i - 1];
				ta[k] = 0;
				bits -= sizeof(T) * 8;
			}

			ocbnonsse<T, N> t;
			if (!bits)
			{
				for (size_t i = 0; i < N; i++)
					t.a[i] = cppcrypto::byteswap(ta[i]);
				return t;
			}
			t.a[0] = cppcrypto::byteswap(ta[0] >> bits);
			for (size_t i = 1; i < N; i++)
			{
				t.a[i] = cppcrypto::byteswap((ta[i] >> bits) | (ta[i - 1] << (sizeof(T)*8 - bits)));
			}

			return t;
		}

		inline ocbnonsse shift_left(size_t bits) const
		{
			T ta[N];
			for (size_t i = 0; i < N; i++)
				ta[i] = cppcrypto::byteswap(a[i]);

			for (size_t b = bits, k = N - 1; b >= sizeof(T)*8; b -= sizeof(T)*8, k--)
			{
				for (size_t i = 0; i < k; i++)
					ta[i] = ta[i + 1];
				ta[k] = 0;
				bits -= sizeof(T) * 8;
			}
			ocbnonsse<T, N> t;
			if (!bits)
			{
				for (size_t i = 0; i < N; i++)
					t.a[i] = cppcrypto::byteswap(ta[i]);
				return t;
			}

			t.a[N - 1] = cppcrypto::byteswap(ta[N - 1] << bits);
			for (size_t i = N - 1; i > 0; i--)
				t.a[i - 1] = cppcrypto::byteswap((ta[i - 1] << bits) | (ta[i] >> (sizeof(T) * 8 - bits)));

			return t;
		}

		uint16_t init_as_nonce(const unsigned char* iv, size_t ivlen, size_t tag_bytes)
		{
			//low = high = 0;
			unsigned char* noncep = reinterpret_cast<unsigned char*>(&a[0]);
			memcpy(noncep + block_bytes - ivlen, iv, ivlen);
			noncep[0] = static_cast<unsigned char>(((tag_bytes * 8) % (block_bytes * 8)) << (8 - ocb_constants<block_bits>::tagrep));
			noncep[block_bytes - ivlen - 1] |= 0x01;

			uint16_t* nonce16p = reinterpret_cast<uint16_t*>(&noncep[block_bytes - 2]);
			uint16_t bottom = *nonce16p & ocb_constants<block_bits>::bottom_mask;
			*nonce16p &= ocb_constants<block_bits>::zero_nonce_mask;

			return cppcrypto::byteswap(bottom);
		}

		inline static void decrypt_block(const ocbnonsse& first, ocbnonsse& second, cppcrypto::block_cipher& cipher)
		{
			cipher.decrypt_block(reinterpret_cast<const unsigned char*>(&first), reinterpret_cast<unsigned char*>(&second));
		}

		inline static void decrypt_8blocks(const ocbnonsse* first, ocbnonsse* second, cppcrypto::block_cipher& cipher)
		{
			cipher.decrypt_blocks(reinterpret_cast<const unsigned char*>(first), reinterpret_cast<unsigned char*>(second), 8);
		}

		inline static void encrypt_block(const ocbnonsse& first, ocbnonsse& second, cppcrypto::block_cipher& cipher)
		{
			cipher.encrypt_block(reinterpret_cast<const unsigned char*>(&first), reinterpret_cast<unsigned char*>(&second));
		}

		inline static void encrypt_8blocks(const ocbnonsse* first, ocbnonsse* second, cppcrypto::block_cipher& cipher)
		{
			cipher.encrypt_blocks(reinterpret_cast<const unsigned char*>(first), reinterpret_cast<unsigned char*>(second), 8);
		}

	};

	template<typename T, size_t N>
	inline ocbnonsse<T,N> operator^(const ocbnonsse<T, N>& first, const ocbnonsse<T, N>& second)
	{
		ocbnonsse<T, N> t = first;
		t ^= second;
		return t;
	}

	template<typename T, size_t N>
	inline ocbnonsse<T, N> operator|(const ocbnonsse<T, N>& first, const ocbnonsse<T, N>& second)
	{
		ocbnonsse<T, N> t = first;
		t |= second;
		return t;
	}

#ifndef NO_OPTIMIZED_VERSIONS
#if defined(__clang__)
#pragma clang attribute push (__attribute__((target("ssse3"))), apply_to=function)
#elif defined(__GNUG__)
#pragma GCC push_options
#pragma GCC target("ssse3")
#endif
	struct sse128
	{
		sse128() {}
		sse128(__m128i v) : val(v) {}

		static const size_t block_bytes = 16;
		static const size_t block_bits = 128;

		static inline sse128 zero() { return _mm_setzero_si128(); }

		inline sse128& operator ^=(const sse128& other)
		{
			val = _mm_xor_si128(val, other.val);
			return *this;
		}

		inline sse128& operator |=(const sse128& other)
		{
			val = _mm_or_si128(val, other.val);
			return *this;
		}

		static inline sse128 load(const unsigned char* in) 
		{ 
			return _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
		}

		static inline sse128 load_partial(const unsigned char* in, size_t bytes)
		{
			unsigned char buf[16];
			memcpy(buf, in, bytes);
			memset(buf + bytes, 0, 16 - bytes);
			return load(buf);
		}

		inline void unload(unsigned char* out) const
		{
			_mm_storeu_si128(reinterpret_cast<__m128i*>(out), val);
		}

		inline void unload_partial(unsigned char* out, size_t bytes) const
		{
			unsigned char buf[16];
			_mm_storeu_si128(reinterpret_cast<__m128i*>(buf), val);
			memcpy(out, buf, bytes);
		}

		static inline sse128 load_partial_with_padding(const unsigned char* in, size_t bytes)
		{
			unsigned char buf[16];
			memcpy(buf, in, bytes);
			memset(buf + bytes, 0, 16 - bytes);
			buf[bytes] = 0x80;
			return load(buf);
		}

		inline void pad(size_t remaining)
		{
			unsigned char buf[16];
			_mm_storeu_si128(reinterpret_cast<__m128i*>(buf), val);
			memset(buf + remaining, 0, 16 - remaining);
			buf[remaining] = 0x80;
			val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf));
		}

		inline sse128 double_block() const
		{
			const __m128i rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
			__m128i sv = _mm_shuffle_epi8(val, rev);
			const __m128i mask = _mm_set_epi32(135, 1, 1, 1);
			__m128i sv31 = _mm_srai_epi32(sv, 31);
			__m128i sv31m = _mm_and_si128(sv31, mask);
			__m128i sv31ms = _mm_shuffle_epi32(sv31m, _MM_SHUFFLE(2, 1, 0, 3));
			__m128i sv1 = _mm_slli_epi32(sv, 1);
			__m128i dv = _mm_xor_si128(sv31ms, sv1);

			return  _mm_shuffle_epi8(dv, rev);
		}

		inline sse128 shift_right(size_t bits) const
		{
			const __m128i rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
			__m128i sv = _mm_shuffle_epi8(val, rev);

			if (bits > 64)
				return _mm_shuffle_epi8(_mm_srli_epi64(_mm_srli_si128(sv, 8), static_cast<int>(bits) - 64), rev);

			__m128i tmp = _mm_slli_epi64(sv, 64 - static_cast<int>(bits));
			tmp = _mm_unpackhi_epi64(tmp, _mm_setzero_si128());
			tmp = _mm_or_si128(_mm_srli_epi64(sv, static_cast<int>(bits)), tmp);
			tmp = _mm_shuffle_epi8(tmp, rev);
			return tmp;
		}

		inline sse128 shift_left(size_t bits) const
		{
			const __m128i rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
			__m128i sv = _mm_shuffle_epi8(val, rev);

			if (bits > 64)
				return _mm_shuffle_epi8(_mm_slli_epi64(_mm_slli_si128(sv, 8), static_cast<int>(bits) - 64), rev);

			__m128i tmp = _mm_srli_epi64(sv, 64 - static_cast<int>(bits));
			tmp = _mm_unpacklo_epi64(_mm_setzero_si128(), tmp);

			tmp = _mm_or_si128(_mm_slli_epi64(sv, static_cast<int>(bits)), tmp);

			tmp = _mm_shuffle_epi8(tmp, rev);
			return tmp;
		}

		uint16_t init_as_nonce(const unsigned char* iv, size_t ivlen, size_t tag_bytes)
		{
			//low = high = 0;
			const size_t tagrep = 7;

			unsigned char noncep[16];
			memset(noncep, 0, block_bytes - ivlen);
			memcpy(noncep + block_bytes - ivlen, iv, ivlen);

			noncep[0] = static_cast<unsigned char>(((tag_bytes * 8) % (block_bytes * 8)) << (8 - tagrep));
			noncep[block_bytes - ivlen - 1] |= 0x01;

			uint16_t bottom = noncep[15] & 0x3F;
			noncep[15] &= 0xC0;
			val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(noncep));

			return bottom;
		}

		inline static void decrypt_block(const sse128& first, sse128& second, cppcrypto::block_cipher& cipher)
		{
			unsigned char buf[16];
			first.unload(buf);
			cipher.decrypt_block(buf, buf);
			second = load(buf);
		}

		inline static void encrypt_block(const sse128& first, sse128& second, cppcrypto::block_cipher& cipher)
		{
			unsigned char buf[16];
			first.unload(buf);
			cipher.encrypt_block(buf, buf);
			second = load(buf);
		}

		inline static void decrypt_8blocks(const sse128* first, sse128* second, cppcrypto::block_cipher& cipher)
		{
			unsigned char buf[16 * 8];
			first[0].unload(buf);
			first[1].unload(buf + 16);
			first[2].unload(buf + 32);
			first[3].unload(buf + 48);
			first[4].unload(buf + 64);
			first[5].unload(buf + 80);
			first[6].unload(buf + 96);
			first[7].unload(buf + 112);
			cipher.decrypt_blocks(buf, buf, 8);
			second[0] = sse128::load(buf);
			second[1] = sse128::load(buf + 16);
			second[2] = sse128::load(buf + 32);
			second[3] = sse128::load(buf + 48);
			second[4] = sse128::load(buf + 64);
			second[5] = sse128::load(buf + 80);
			second[6] = sse128::load(buf + 96);
			second[7] = sse128::load(buf + 112);
		}

		inline static void encrypt_8blocks(const sse128* first, sse128* second, cppcrypto::block_cipher& cipher)
		{
			unsigned char buf[16 * 8];
			first[0].unload(buf);
			first[1].unload(buf + 16);
			first[2].unload(buf + 32);
			first[3].unload(buf + 48);
			first[4].unload(buf + 64);
			first[5].unload(buf + 80);
			first[6].unload(buf + 96);
			first[7].unload(buf + 112);
			cipher.encrypt_blocks(buf, buf, 8);
			second[0] = sse128::load(buf);
			second[1] = sse128::load(buf + 16);
			second[2] = sse128::load(buf + 32);
			second[3] = sse128::load(buf + 48);
			second[4] = sse128::load(buf + 64);
			second[5] = sse128::load(buf + 80);
			second[6] = sse128::load(buf + 96);
			second[7] = sse128::load(buf + 112);
		}

		__m128i val;
	};

	inline sse128 operator^(const sse128& first, const sse128& second)
	{
		return sse128(_mm_xor_si128(first.val, second.val));
	}

	inline sse128 operator|(const sse128& first, const sse128& second)
	{
		return sse128(_mm_or_si128(first.val, second.val));
	}
#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUG__)
#pragma GCC pop_options
#endif
#endif

	template<typename blocktype>
	inline void hash(const unsigned char* in, size_t inlen, unsigned char* out, cppcrypto::block_cipher& cipher, blocktype* l, blocktype l_star)
	{
		blocktype offset = blocktype::zero();
		blocktype sum = blocktype::zero();
		size_t block_bits = cipher.blocksize();
		size_t block_bytes = block_bits / 8;
		uint64_t fullblocks = inlen / block_bytes;
		uint64_t i = 1;
		if (fullblocks >= 8)
		{
			for (; i < fullblocks - 7; in += block_bits)
			{
				blocktype offsets[8], tmp[8];
				tmp[0] = l[count_trailing_zeroes(i++)];
				tmp[1] = l[count_trailing_zeroes(i++)];
				tmp[2] = l[count_trailing_zeroes(i++)];
				tmp[3] = l[count_trailing_zeroes(i++)];
				tmp[4] = l[count_trailing_zeroes(i++)];
				tmp[5] = l[count_trailing_zeroes(i++)];
				tmp[6] = l[count_trailing_zeroes(i++)];
				tmp[7] = l[count_trailing_zeroes(i++)];
				offsets[0] = offset ^ tmp[0];
				offsets[1] = offsets[0] ^ tmp[1];
				offsets[2] = offsets[1] ^ tmp[2];
				offsets[3] = offsets[2] ^ tmp[3];
				offsets[4] = offsets[3] ^ tmp[4];
				offsets[5] = offsets[4] ^ tmp[5];
				offsets[6] = offsets[5] ^ tmp[6];
				offset = offsets[7] = offsets[6] ^ tmp[7];
				tmp[0] = offsets[0] ^ blocktype::load(in);
				tmp[1] = offsets[1] ^ blocktype::load(in + block_bytes);
				tmp[2] = offsets[2] ^ blocktype::load(in + block_bytes * 2);
				tmp[3] = offsets[3] ^ blocktype::load(in + block_bytes * 3);
				tmp[4] = offsets[4] ^ blocktype::load(in + block_bytes * 4);
				tmp[5] = offsets[5] ^ blocktype::load(in + block_bytes * 5);
				tmp[6] = offsets[6] ^ blocktype::load(in + block_bytes * 6);
				tmp[7] = offsets[7] ^ blocktype::load(in + block_bytes * 7);
				blocktype::encrypt_8blocks(tmp, tmp, cipher);
				sum ^= tmp[0];
				sum ^= tmp[1];
				sum ^= tmp[2];
				sum ^= tmp[3];
				sum ^= tmp[4];
				sum ^= tmp[5];
				sum ^= tmp[6];
				sum ^= tmp[7];
			}
		}
		for (; i <= fullblocks; in += block_bytes)
		{
			blocktype tmp = l[count_trailing_zeroes(i++)];
			offset ^= tmp;
			tmp = offset ^ blocktype::load(in);
			blocktype::encrypt_block(tmp, tmp, cipher);
			sum ^= tmp;
		}
		size_t remaining = inlen - static_cast<size_t>(fullblocks) * block_bytes;
		if (remaining)
		{
			offset ^= l_star;
			blocktype tmp = blocktype::load_partial_with_padding(in, remaining);
			tmp ^= offset;
			blocktype::encrypt_block(tmp, tmp, cipher);
			sum ^= tmp;
		}

		memcpy(out, &sum, block_bytes);
	}

	template<typename blocktype>
	class ocb_impl_tpl : public detail::ocb_impl
	{
	public:
		ocb_impl_tpl(const block_cipher& cipher) : cipher_encrypt(cipher.clone()), cipher_decrypt(cipher.clone()) {}

		~ocb_impl_tpl()
		{
			for (int i = 0; i < 64; i++)
				l_[i] = blocktype::zero();
			l_star_ = blocktype::zero();
			l_dollar_ = blocktype::zero();
		}

		void set_key(const unsigned char* key, size_t keylen) override
		{
			if (keylen != keysize_in_bytes())
				throw std::runtime_error("invalid key size");

			cipher_encrypt->init(key, cipher_encrypt->encryption);
			cipher_decrypt->init(key, cipher_decrypt->decryption);

			l_star_ = blocktype::zero();
			blocktype::encrypt_block(l_star_, l_star_, *cipher_encrypt);

			l_dollar_ = l_star_.double_block();
			l_[0] = l_dollar_.double_block();
			for (int i = 1; i < 64; i++)
				l_[i] = l_[i - 1].double_block();
		}

		void encrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out, size_t tag_bytes) override
		{
			blocktype l_star = l_star_;
			blocktype l_dollar = l_dollar_;
			blocktype l[64];
			for (int i = 0; i < 64; i++)
				l[i] = l_[i];
			const size_t block_bits = cipher_encrypt->blocksize();
			const size_t block_bytes = block_bits / 8;

			blocktype nonce = blocktype::zero();
			uint16_t bottom = nonce.init_as_nonce(iv, ivlen, tag_bytes);
			blocktype ktop;
			blocktype::encrypt_block(nonce, ktop, *cipher_encrypt);
			blocktype shiftedktop = ktop.shift_left(ocb_constants<blocktype::block_bits>::shift) ^ ktop;

			blocktype offset = bottom ? (ktop.shift_left(bottom) | shiftedktop.shift_right(block_bits - bottom)) : ktop;

			blocktype sum = blocktype::zero();
			blocktype tag;
			hash<blocktype>(ad, adlen, reinterpret_cast<unsigned char*>(&tag), *cipher_encrypt, l, l_star);

			uint64_t i = 1;
			uint64_t fullblocks = inlen / block_bytes;

			if (fullblocks >= 8)
			{
				for (; i < fullblocks - 7; in += block_bits, out += block_bits)
				{
					blocktype offsets[8], tmp[8];
					tmp[0] = l[count_trailing_zeroes(i++)];
					tmp[1] = l[count_trailing_zeroes(i++)];
					tmp[2] = l[count_trailing_zeroes(i++)];
					tmp[3] = l[count_trailing_zeroes(i++)];
					tmp[4] = l[count_trailing_zeroes(i++)];
					tmp[5] = l[count_trailing_zeroes(i++)];
					tmp[6] = l[count_trailing_zeroes(i++)];
					tmp[7] = l[count_trailing_zeroes(i++)];
					offsets[0] = offset ^ tmp[0];
					offsets[1] = offsets[0] ^ tmp[1];
					offsets[2] = offsets[1] ^ tmp[2];
					offsets[3] = offsets[2] ^ tmp[3];
					offsets[4] = offsets[3] ^ tmp[4];
					offsets[5] = offsets[4] ^ tmp[5];
					offsets[6] = offsets[5] ^ tmp[6];
					offset = offsets[7] = offsets[6] ^ tmp[7];

					tmp[0] = blocktype::load(in);
					tmp[1] = blocktype::load(in + block_bytes);
					tmp[2] = blocktype::load(in + block_bytes * 2);
					tmp[3] = blocktype::load(in + block_bytes * 3);
					tmp[4] = blocktype::load(in + block_bytes * 4);
					tmp[5] = blocktype::load(in + block_bytes * 5);
					tmp[6] = blocktype::load(in + block_bytes * 6);
					tmp[7] = blocktype::load(in + block_bytes * 7);

					sum ^= tmp[0];
					sum ^= tmp[1];
					sum ^= tmp[2];
					sum ^= tmp[3];
					sum ^= tmp[4];
					sum ^= tmp[5];
					sum ^= tmp[6];
					sum ^= tmp[7];

					tmp[0] ^= offsets[0];
					tmp[1] ^= offsets[1];
					tmp[2] ^= offsets[2];
					tmp[3] ^= offsets[3];
					tmp[4] ^= offsets[4];
					tmp[5] ^= offsets[5];
					tmp[6] ^= offsets[6];
					tmp[7] ^= offsets[7];

					blocktype::encrypt_8blocks(tmp, tmp, *cipher_encrypt);

					tmp[0] ^= offsets[0];
					tmp[1] ^= offsets[1];
					tmp[2] ^= offsets[2];
					tmp[3] ^= offsets[3];
					tmp[4] ^= offsets[4];
					tmp[5] ^= offsets[5];
					tmp[6] ^= offsets[6];
					tmp[7] ^= offsets[7];
					memcpy(out, tmp, block_bits);
				}
			}

			for (; i <= fullblocks; in += block_bytes, out += block_bytes)
			{
				blocktype tmp = l[count_trailing_zeroes(i++)];
				offset ^= tmp;
				tmp = blocktype::load(in);
				sum ^= tmp;
				tmp ^= offset;
				blocktype::encrypt_block(tmp, tmp, *cipher_encrypt);
				tmp ^= offset;
				tmp.unload(out);
			}

			size_t remaining = inlen - static_cast<size_t>(fullblocks) * block_bytes;
			if (remaining)
			{
				offset ^= l_star;
				blocktype paddedP = blocktype::load_partial_with_padding(in, remaining);
				blocktype pad;
				blocktype::encrypt_block(offset, pad, *cipher_encrypt);

				sum ^= paddedP;
				pad ^= paddedP;
				pad.unload_partial(out, remaining);
				out += remaining;
			}

			sum ^= offset;
			sum ^= l_dollar;

			blocktype::encrypt_block(sum, offset, *cipher_encrypt);
			tag ^= offset;
			tag.unload_partial(out, tag_bytes);
		}

		bool decrypt(const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, size_t ivlen, unsigned char* out, size_t tag_bytes) override
		{
			blocktype l_star = l_star_;
			blocktype l_dollar = l_dollar_;
			blocktype l[64];
			for (int i = 0; i < 64; i++)
				l[i] = l_[i];
			const size_t block_bits = cipher_encrypt->blocksize();
			const size_t block_bytes = block_bits / 8;

			blocktype nonce = blocktype::zero();
			uint16_t bottom = nonce.init_as_nonce(iv, ivlen, tag_bytes);

			blocktype ktop;
			blocktype::encrypt_block(nonce, ktop, *cipher_encrypt);

			blocktype shiftedktop = ktop.shift_left(ocb_constants<blocktype::block_bits>::shift) ^ ktop;
			blocktype offset = bottom ? (ktop.shift_left(bottom) | shiftedktop.shift_right(block_bits - bottom)) : ktop;
			blocktype sum = blocktype::zero();

			blocktype tag;
			hash(ad, adlen, reinterpret_cast<unsigned char*>(&tag), *cipher_encrypt, l, l_star);

			uint64_t i = 1;
			inlen -= tag_bytes;
			uint64_t fullblocks = inlen / block_bytes;

			if (fullblocks >= 8)
			{
				for (; i < fullblocks - 7; in += block_bits, out += block_bits)
				{
					blocktype offsets[8], tmp[8];
					tmp[0] = l[count_trailing_zeroes(i++)];
					tmp[1] = l[count_trailing_zeroes(i++)];
					tmp[2] = l[count_trailing_zeroes(i++)];
					tmp[3] = l[count_trailing_zeroes(i++)];
					tmp[4] = l[count_trailing_zeroes(i++)];
					tmp[5] = l[count_trailing_zeroes(i++)];
					tmp[6] = l[count_trailing_zeroes(i++)];
					tmp[7] = l[count_trailing_zeroes(i++)];

					offsets[0] = offset ^ tmp[0];
					offsets[1] = offsets[0] ^ tmp[1];
					offsets[2] = offsets[1] ^ tmp[2];
					offsets[3] = offsets[2] ^ tmp[3];
					offsets[4] = offsets[3] ^ tmp[4];
					offsets[5] = offsets[4] ^ tmp[5];
					offsets[6] = offsets[5] ^ tmp[6];
					offset = offsets[7] = offsets[6] ^ tmp[7];

					tmp[0] = blocktype::load(in);
					tmp[1] = blocktype::load(in + block_bytes);
					tmp[2] = blocktype::load(in + block_bytes * 2);
					tmp[3] = blocktype::load(in + block_bytes * 3);
					tmp[4] = blocktype::load(in + block_bytes * 4);
					tmp[5] = blocktype::load(in + block_bytes * 5);
					tmp[6] = blocktype::load(in + block_bytes * 6);
					tmp[7] = blocktype::load(in + block_bytes * 7);

					tmp[0] ^= offsets[0];
					tmp[1] ^= offsets[1];
					tmp[2] ^= offsets[2];
					tmp[3] ^= offsets[3];
					tmp[4] ^= offsets[4];
					tmp[5] ^= offsets[5];
					tmp[6] ^= offsets[6];
					tmp[7] ^= offsets[7];

					blocktype::decrypt_8blocks(tmp, tmp, *cipher_decrypt);

					tmp[0] ^= offsets[0];
					tmp[1] ^= offsets[1];
					tmp[2] ^= offsets[2];
					tmp[3] ^= offsets[3];
					tmp[4] ^= offsets[4];
					tmp[5] ^= offsets[5];
					tmp[6] ^= offsets[6];
					tmp[7] ^= offsets[7];

					sum ^= tmp[0];
					sum ^= tmp[1];
					sum ^= tmp[2];
					sum ^= tmp[3];
					sum ^= tmp[4];
					sum ^= tmp[5];
					sum ^= tmp[6];
					sum ^= tmp[7];

					memcpy(out, tmp, block_bits);
				}
			}

			for (; i <= fullblocks; in += block_bytes, out += block_bytes)
			{
				offset ^= l[count_trailing_zeroes(i++)];
				blocktype tmp = blocktype::load(in);
				tmp ^= offset;
				blocktype::decrypt_block(tmp, tmp, *cipher_decrypt);
				tmp ^= offset;
				sum ^= tmp;
				tmp.unload(out);
			}

			size_t remaining = inlen - static_cast<size_t>(fullblocks) * block_bytes;
			if (remaining)
			{
				offset ^= l_star;
				blocktype pad;
				blocktype::encrypt_block(offset, pad, *cipher_encrypt);

				blocktype paddedP = blocktype::load_partial(in, remaining);
				paddedP ^= pad;
				paddedP.unload_partial(out, remaining);
				paddedP.pad(remaining);

				sum ^= paddedP;
				in += remaining;
			}

			sum ^= offset;
			sum ^= l_dollar;
			blocktype::encrypt_block(sum, offset, *cipher_encrypt);
			tag ^= offset;

			return cppcrypto::tag_matches(reinterpret_cast<const unsigned char*>(&tag), in, tag_bytes);
		}

		size_t max_iv_bytes() const override
		{
			return ocb_constants<blocktype::block_bits>::max_iv_bytes;
		}

		size_t keysize_in_bytes() const override
		{
			return cipher_encrypt->keysize() / 8;
		}


		const std::unique_ptr<block_cipher>& get_cipher() const override
		{
			return cipher_encrypt;
		}

	private:
		blocktype l_[64];
		blocktype l_star_ = blocktype::zero();
		blocktype l_dollar_ = blocktype::zero();
		std::unique_ptr<block_cipher> cipher_encrypt;
		std::unique_ptr<block_cipher> cipher_decrypt;
   };

}


	aead_ocb::aead_ocb(const block_cipher& cipher)
		: tagsize_in_bits(std::min(cipher.blocksize(), static_cast<size_t>(256)))
	{
		switch(cipher.blocksize())
		{
			case 128:
#ifndef NO_OPTIMIZED_VERSIONS
				if (cpu_info::ssse3())
					impl_.create<ocb_impl_tpl<sse128>>(cipher);
				else
#endif
					impl_.create<ocb_impl_tpl<ocbnonsse<uint64_t, 2>>>(cipher);
				break;
			case 160:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint32_t, 5>>>(cipher);
				break;
			case 192:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint64_t, 3>>>(cipher);
				break;
			case 224:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint32_t, 7>>>(cipher);
				break;
			case 256:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint64_t, 4>>>(cipher);
				break;
			case 512:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint64_t, 8>>>(cipher);
				break;
			case 1024:
				impl_.create<ocb_impl_tpl<ocbnonsse<uint64_t, 16>>>(cipher);
				break;
			default:
				throw std::runtime_error("ocb for specified blocksize is not implemented");
		}

	}

	aead_ocb::~aead_ocb()
	{
	}

	void aead_ocb::set_key(const unsigned char* key, size_t keylen)
	{
		impl_->set_key(key, keylen);
		initialized_ = true;
	}

	size_t aead_ocb::iv_bytes() const
	{
		return impl_->max_iv_bytes();
	}

	void aead_ocb::set_tagsize_in_bits(size_t tagsize)
	{
		if (tagsize < 1 || tagsize > std::min(static_cast<size_t>(256), impl_->get_cipher()->blocksize()) || tagsize % 8 != 0)
			throw std::runtime_error("invalid ocb tag length");

		tagsize_in_bits = tagsize;
	}

	void aead_ocb::do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!initialized_)
			throw std::runtime_error("key not set");

		if (iv_len > iv_bytes())
			throw std::runtime_error("incorrect iv size");

		impl_->encrypt(plaintext, plaintext_len, associated_data, associated_data_len, iv, iv_len, result, tag_bytes());
	}

	bool aead_ocb::do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!initialized_)
			throw std::runtime_error("key not set");

		if (iv_len > iv_bytes())
			throw std::runtime_error("incorrect iv size");

		if (ciphertext_len < tag_bytes())
			return false;

		return impl_->decrypt(ciphertext, ciphertext_len, associated_data, associated_data_len, iv, iv_len, result, tag_bytes());
	}

	aead_ocb* aead_ocb::clone() const
	{
		auto res = new aead_ocb(*impl_->get_cipher());
		res->set_tagsize_in_bits(tagsize_in_bits);
		return res; 
	}

}

