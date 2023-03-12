/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "aead_gcm.h"
#include "functions.h"
#include "portability.h"
#include "random_bytes.h"
#include <stdexcept>
#include <string.h>
//#define NO_OPTIMIZED_VERSIONS
#include "cpuinfo.h"

#include <tmmintrin.h>

namespace cppcrypto
{
    namespace
    {
        static const uint16_t R[256] = {
            0x0000, 0xc201, 0x8403, 0x4602, 0x0807, 0xca06, 0x8c04, 0x4e05,
            0x100e, 0xd20f, 0x940d, 0x560c, 0x1809, 0xda08, 0x9c0a, 0x5e0b,
            0x201c, 0xe21d, 0xa41f, 0x661e, 0x281b, 0xea1a, 0xac18, 0x6e19,
            0x3012, 0xf213, 0xb411, 0x7610, 0x3815, 0xfa14, 0xbc16, 0x7e17,
            0x4038, 0x8239, 0xc43b, 0x063a, 0x483f, 0x8a3e, 0xcc3c, 0x0e3d,
            0x5036, 0x9237, 0xd435, 0x1634, 0x5831, 0x9a30, 0xdc32, 0x1e33,
            0x6024, 0xa225, 0xe427, 0x2626, 0x6823, 0xaa22, 0xec20, 0x2e21,
            0x702a, 0xb22b, 0xf429, 0x3628, 0x782d, 0xba2c, 0xfc2e, 0x3e2f,
            0x8070, 0x4271, 0x0473, 0xc672, 0x8877, 0x4a76, 0x0c74, 0xce75,
            0x907e, 0x527f, 0x147d, 0xd67c, 0x9879, 0x5a78, 0x1c7a, 0xde7b,
            0xa06c, 0x626d, 0x246f, 0xe66e, 0xa86b, 0x6a6a, 0x2c68, 0xee69,
            0xb062, 0x7263, 0x3461, 0xf660, 0xb865, 0x7a64, 0x3c66, 0xfe67,
            0xc048, 0x0249, 0x444b, 0x864a, 0xc84f, 0x0a4e, 0x4c4c, 0x8e4d,
            0xd046, 0x1247, 0x5445, 0x9644, 0xd841, 0x1a40, 0x5c42, 0x9e43,
            0xe054, 0x2255, 0x6457, 0xa656, 0xe853, 0x2a52, 0x6c50, 0xae51,
            0xf05a, 0x325b, 0x7459, 0xb658, 0xf85d, 0x3a5c, 0x7c5e, 0xbe5f,
            0x00e1, 0xc2e0, 0x84e2, 0x46e3, 0x08e6, 0xcae7, 0x8ce5, 0x4ee4,
            0x10ef, 0xd2ee, 0x94ec, 0x56ed, 0x18e8, 0xdae9, 0x9ceb, 0x5eea,
            0x20fd, 0xe2fc, 0xa4fe, 0x66ff, 0x28fa, 0xeafb, 0xacf9, 0x6ef8,
            0x30f3, 0xf2f2, 0xb4f0, 0x76f1, 0x38f4, 0xfaf5, 0xbcf7, 0x7ef6,
            0x40d9, 0x82d8, 0xc4da, 0x06db, 0x48de, 0x8adf, 0xccdd, 0x0edc,
            0x50d7, 0x92d6, 0xd4d4, 0x16d5, 0x58d0, 0x9ad1, 0xdcd3, 0x1ed2,
            0x60c5, 0xa2c4, 0xe4c6, 0x26c7, 0x68c2, 0xaac3, 0xecc1, 0x2ec0,
            0x70cb, 0xb2ca, 0xf4c8, 0x36c9, 0x78cc, 0xbacd, 0xfccf, 0x3ece,
            0x8091, 0x4290, 0x0492, 0xc693, 0x8896, 0x4a97, 0x0c95, 0xce94,
            0x909f, 0x529e, 0x149c, 0xd69d, 0x9898, 0x5a99, 0x1c9b, 0xde9a,
            0xa08d, 0x628c, 0x248e, 0xe68f, 0xa88a, 0x6a8b, 0x2c89, 0xee88,
            0xb083, 0x7282, 0x3480, 0xf681, 0xb884, 0x7a85, 0x3c87, 0xfe86,
            0xc0a9, 0x02a8, 0x44aa, 0x86ab, 0xc8ae, 0x0aaf, 0x4cad, 0x8eac,
            0xd0a7, 0x12a6, 0x54a4, 0x96a5, 0xd8a0, 0x1aa1, 0x5ca3, 0x9ea2,
            0xe0b5, 0x22b4, 0x64b6, 0xa6b7, 0xe8b2, 0x2ab3, 0x6cb1, 0xaeb0,
            0xf0bb, 0x32ba, 0x74b8, 0xb6b9, 0xf8bc, 0x3abd, 0x7cbf, 0xbebe
        };

        static void generate_tables(unsigned char* hkey, uint64_t tables[16][256][2])
        {
            // algorithm as described in section 4.1 of GCM spec
            memcpy(tables[0][128], hkey, 16);
            for (int n = 0; n < 16; n++)
            {
                auto tl = tables[n];
                if (n)
                {
                    uint64_t prev0 = tables[n - 1][128][0];
                    uint64_t prev1 = tables[n - 1][128][1];
                    tl[128][1] = (prev1 << 8 | prev0 >> 56);
                    tl[128][0] = (prev0 << 8) ^ R[prev1 >> 56];
                }

                for (int i = 64; i > 0; i /= 2)
                {
                    memcpy(tl[i], tl[i << 1], 16);
                    bool overflowtl = (tl[i][1] & 0x0100000000000000ull) != 0ull;
                    tl[i][1] = swap_uint64((swap_uint64(tl[i][0]) << 63) | (swap_uint64(tl[i][1]) >> 1));
                    tl[i][0] = swap_uint64((swap_uint64(tl[i][0]) >> 1));
                    if (overflowtl)
                        tl[i][0] ^= 0xE1ull;
                }

                for (int i = 2; i <= 128; i *= 2)
                {
                    for (int j = 1; j < i; j++)
                    {
                        tl[i + j][0] = tl[i][0] ^ tl[j][0];
                        tl[i + j][1] = tl[i][1] ^ tl[j][1];
                    }
                }

                tl[0][0] = tl[0][1] = 0ull;
            }
        }

        inline static void gcm_mult(uint64_t T[16][256][2], unsigned char* z, const unsigned char* x)
        {
            uint64_t z0 = T[0][z[0]][0] ^ T[1][z[1]][0] ^ T[2][z[2]][0] ^ T[3][z[3]][0] ^ T[4][z[4]][0] ^ T[5][z[5]][0] ^ T[6][z[6]][0] ^ T[7][z[7]][0]
                ^ T[8][z[8]][0] ^ T[9][z[9]][0] ^ T[10][z[10]][0] ^ T[11][z[11]][0] ^ T[12][z[12]][0] ^ T[13][z[13]][0] ^ T[14][z[14]][0] ^ T[15][z[15]][0];
            uint64_t z1 = T[0][z[0]][1] ^ T[1][z[1]][1] ^ T[2][z[2]][1] ^ T[3][z[3]][1] ^ T[4][z[4]][1] ^ T[5][z[5]][1] ^ T[6][z[6]][1] ^ T[7][z[7]][1]
                ^ T[8][z[8]][1] ^ T[9][z[9]][1] ^ T[10][z[10]][1] ^ T[11][z[11]][1] ^ T[12][z[12]][1] ^ T[13][z[13]][1] ^ T[14][z[14]][1] ^ T[15][z[15]][1];

            *(((uint64_t*)z) + 0) = z0;
            *(((uint64_t*)z) + 1) = z1;
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

        inline static void gcm_xor_16_mult(uint64_t T[16][256][2], unsigned char* z, const unsigned char* x)
        {
            xor_block_128(z, x, z);
            gcm_mult(T, z, x);
        }

        inline static void gcm_xor_n_mult(uint64_t T[16][256][2], unsigned char* z, const unsigned char* x, unsigned long long x_len)
        {
            for (size_t i = 0; i < x_len; ++i)
                z[i] ^= x[i];

            gcm_mult(T, z, x);
        }

        inline static void init_iv(uint64_t table[16][256][2], const unsigned char* iv, size_t iv_len, unsigned char* j, unsigned char* lengths)
        {
            if (iv_len == 12)
            {
                memcpy(j, iv, 12);
                *reinterpret_cast<uint32_t*>(j + 12) = swap_uint32(1);
            }
            else
            {
                memset(j, 0, 16);
                for (size_t i = 0; i < iv_len; i += 16)
                {
                    if (i + 16 < iv_len)
                    {
                        gcm_xor_16_mult(table, j, iv + i);
                    }
                    else
                    {
                        memcpy(lengths, iv + i, iv_len - i);
                        memset(lengths + iv_len - i, 0, 16 + i - iv_len);
                        gcm_xor_16_mult(table, j, lengths);
                    }
                }
                memset(lengths, 0, 8);
                *reinterpret_cast<uint64_t*>(lengths + 8) = swap_uint64(iv_len * 8);
                gcm_xor_16_mult(table, j, lengths);
            }
        }


#if 0
        static void generate_R()
        {
            printf("static const uint16_t R[256] = {\n\t");
            for (int i = 0; i < 256; i++)
            {
                uint16_t t = i << 8;
                uint16_t a = swap_uint16((t ^ (t >> 1) ^ (t >> 2) ^ (t >> 7)));
                printf("0x%04x", a);
                if (i != 255)
                    printf(", ");
                if (i % 8 == 7)
                    printf("\n\t");
            }
            printf("\n\t};");
        }
#endif

        class gcm64k : public detail::gcm_impl
        {
        public:
            gcm64k(const block_cipher& cipher) : detail::gcm_impl(cipher)
            {
            }

            ~gcm64k()
            {
                zero_memory(table, sizeof(table));
            }

            void set_key(const unsigned char* key, size_t keylen)
            {
                unsigned char zero_block[16];
                memset(zero_block, 0, 16);
                cipher_->init(key, cppcrypto::block_cipher::encryption);
                cipher_->encrypt_block(zero_block, zero_block);
                generate_tables(zero_block, table);
            }

            void encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
            {
                unsigned char j[16], lengths[16];
                init_iv(table, iv, iv_len, j, lengths);

                uint32_t* rpindex = reinterpret_cast<uint32_t*>(j + 12);

                *reinterpret_cast<uint64_t*>(lengths) = swap_uint64(associated_data_len * 8);
                *reinterpret_cast<uint64_t*>(lengths + 8) = swap_uint64(plaintext_len * 8);

                unsigned char tag[16];
                memset(tag, 0, sizeof(tag));
                while (associated_data_len > 15)
                {
                    gcm_xor_16_mult(table, tag, associated_data);
                    associated_data += 16;
                    associated_data_len -= 16;
                }
                if (associated_data_len > 0)
                    gcm_xor_n_mult(table, tag, associated_data, associated_data_len);

                uint32_t revindex = *rpindex;
                uint32_t index = swap_uint32(revindex);
                unsigned char ct[16];
                while (plaintext_len > 15)
                {
                    *rpindex = swap_uint32(++index);
                    cipher_->encrypt_block(j, ct);
                    xor_block_128(plaintext, ct, result);
                    gcm_xor_16_mult(table, tag, result);
                    plaintext += 16;
                    result += 16;
                    plaintext_len -= 16;
                }
                if (plaintext_len > 0)
                {
                    *rpindex = swap_uint32(++index);
                    cipher_->encrypt_block(j, ct);
                    for (size_t i = 0; i < plaintext_len; ++i)
                        result[i] = plaintext[i] ^ ct[i];
                    gcm_xor_n_mult(table, tag, result, plaintext_len);
                    result += plaintext_len;
                }
                gcm_xor_16_mult(table, tag, lengths);

                *rpindex = revindex;
                cipher_->encrypt_block(j, j);

		if (tagsize_in_bytes() == 16)
                	xor_block_128(j, tag, result);
		else
		{
                	xor_block_128(j, tag, ct);
			memcpy(result, ct, tagsize_in_bytes());
		}
            }

            bool decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
            {
                unsigned char j[16], lengths[16];
                init_iv(table, iv, iv_len, j, lengths);
                size_t plaintext_len = ciphertext_len - tagsize_in_bytes();
                uint32_t* rpindex = reinterpret_cast<uint32_t*>(j + 12);

                *reinterpret_cast<uint64_t*>(lengths) = swap_uint64(associated_data_len * 8);
                *reinterpret_cast<uint64_t*>(lengths + 8) = swap_uint64(plaintext_len * 8);

                unsigned char tag[16];
                memset(tag, 0, sizeof(tag));
                while (associated_data_len > 15)
                {
                    gcm_xor_16_mult(table, tag, associated_data);
                    associated_data += 16;
                    associated_data_len -= 16;
                }
                if (associated_data_len > 0)
                    gcm_xor_n_mult(table, tag, associated_data, associated_data_len);

                const unsigned char* savedct = ciphertext;
                size_t savedptlen = plaintext_len;
                while (plaintext_len > 15)
                {
                    gcm_xor_16_mult(table, tag, ciphertext);
                    ciphertext += 16;
                    plaintext_len -= 16;
                }
                if (plaintext_len > 0)
                {
                    gcm_xor_n_mult(table, tag, ciphertext, plaintext_len);
                    ciphertext += plaintext_len;
                }

                gcm_xor_16_mult(table, tag, lengths);

                uint32_t index = swap_uint32(*rpindex);
                unsigned char ct[16];
                cipher_->encrypt_block(j, ct);
                xor_block_128(ct, tag, tag);

                if (!tag_matches(tag, ciphertext, tagsize_in_bytes()))
                    return false;

                while (savedptlen > 15)
                {
                    *rpindex = swap_uint32(++index);
                    cipher_->encrypt_block(j, ct);
                    xor_block_128(savedct, ct, result);
                    savedct += 16;
                    result += 16;
                    savedptlen -= 16;
                }
                if (savedptlen > 0)
                {
                    *rpindex = swap_uint32(++index);
                    cipher_->encrypt_block(j, ct);
                    for (size_t i = 0; i < savedptlen; ++i)
                        result[i] = savedct[i] ^ ct[i];
                }

                return true;
            }

        private:
            uint64_t table[16][256][2];
        };
    }

	aead_gcm::aead_gcm(const block_cipher& cipher)
	{
		if (cipher.blocksize() != 128)
			throw std::runtime_error("gcm is defined only for ciphers with blocksize 128");

#ifndef NO_OPTIMIZED_VERSIONS
        if (cpu_info().pclmulqdq() && cpu_info().aesni())
            impl_.reset(new detail::gcm_impl_clmul(cipher));
        else
#endif
            impl_.reset(new gcm64k(cipher));
	}

	aead_gcm::~aead_gcm()
	{
	}

	void aead_gcm::set_key(const unsigned char* key, size_t keylen)
	{
		impl_->set_key(key, keylen);
		initialized_ = true;
	}

	void aead_gcm::set_tagsize_in_bits(size_t tagsize)
	{
		if (!tagsize || tagsize > 128 || tagsize % 8 != 0)
			throw std::runtime_error("invalid tag size");

		impl_->set_tagsize_in_bits(tagsize);
	}

	size_t aead_gcm::iv_bytes() const
	{
		return 12;
	}

	void aead_gcm::do_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!initialized_)
			throw std::runtime_error("key not set");

        if (iv_len < 1)
			throw std::runtime_error("incorrect iv size");

		impl_->encrypt(plaintext, plaintext_len, associated_data, associated_data_len, iv, iv_len, result);
	}

	bool aead_gcm::do_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, const unsigned char* iv, size_t iv_len, unsigned char* result)
	{
		if (!initialized_)
			throw std::runtime_error("key not set");

        if (iv_len < 1)
            throw std::runtime_error("incorrect iv size");

		if (ciphertext_len < tag_bytes())
			return false;

		return impl_->decrypt(ciphertext, ciphertext_len, associated_data, associated_data_len, iv, iv_len, result);
	}

}

