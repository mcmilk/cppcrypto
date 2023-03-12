/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "schwaemm_impl.h"
#include "portability.h"
#include "functions.h"
#include <string.h>

namespace cppcrypto
{
    namespace detail
    {
        namespace
        {
            const uint32_t C[8] = {
                0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738, 0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d
            };
        }

        void schwaemm_impl::set_tagsize_in_bits(size_t tagsize)
        {
            if (!tagsize || tagsize > tagsize_in_bytes_default() * 8 || tagsize % 8 != 0)
                throw std::runtime_error("invalid tag size");

            tagsize_in_bits = tagsize;
        }

        size_t schwaemm_impl::tagsize_in_bytes() const
        {
            if (tagsize_in_bits == SIZE_MAX)
                return tagsize_in_bytes_default();
            return tagsize_in_bits / 8;
        }

        schwaemm256_128::schwaemm256_128()
        {
            clear();
        }

        schwaemm256_128::~schwaemm256_128()
        {
            clear();
        }

        void schwaemm256_128::clear()
        {
            zero_memory(nonHHx, sizeof(nonHHx));
            zero_memory(nonHHy, sizeof(nonHHy));
        }

        inline void schwaemm256_128::sparkle_step_common(int i)
        {
            nonHHy[0] ^= C[i % 8];
            nonHHy[1] ^= static_cast<uint32_t>(i);

            for (int r = 0; r < 6; r++)
            {
                nonHHx[r] += rotater32(nonHHy[r], 31);
                nonHHy[r] ^= rotater32(nonHHx[r], 24);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 17);
                nonHHy[r] ^= rotater32(nonHHx[r], 17);
                nonHHx[r] ^= C[r];
                nonHHx[r] += nonHHy[r];
                nonHHy[r] ^= rotater32(nonHHx[r], 31);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 24);
                nonHHy[r] ^= rotater32(nonHHx[r], 16);
                nonHHx[r] ^= C[r];
            }
        }

        inline void schwaemm256_128::sparkle_step_384(int i)
        {
            sparkle_step_common(i);

            uint32_t tx = nonHHx[0] ^ nonHHx[1] ^ nonHHx[2];
            uint32_t ty = nonHHy[0] ^ nonHHy[1] ^ nonHHy[2];
            tx = rotatel32(tx ^ (tx << 16), 16);
            ty = rotatel32(ty ^ (ty << 16), 16);

            nonHHx[3] ^= nonHHx[0] ^ ty;
            nonHHx[4] ^= nonHHx[1] ^ ty;
            nonHHx[5] ^= nonHHx[2] ^ ty;
            nonHHy[3] ^= nonHHy[0] ^ tx;
            nonHHy[4] ^= nonHHy[1] ^ tx;
            nonHHy[5] ^= nonHHy[2] ^ tx;

            tx = nonHHx[0];
            nonHHx[0] = nonHHx[4];
            nonHHx[4] = nonHHx[1];
            nonHHx[1] = nonHHx[5];
            nonHHx[5] = nonHHx[2];
            nonHHx[2] = nonHHx[3];
            nonHHx[3] = tx;

            ty = nonHHy[0];
            nonHHy[0] = nonHHy[4];
            nonHHy[4] = nonHHy[1];
            nonHHy[1] = nonHHy[5];
            nonHHy[5] = nonHHy[2];
            nonHHy[2] = nonHHy[3];
            nonHHy[3] = ty;
        }

        inline void schwaemm256_128::sparkle384_big()
        {
            sparkle_step_384(0);
            sparkle_step_384(1);
            sparkle_step_384(2);
            sparkle_step_384(3);
            sparkle_step_384(4);
            sparkle_step_384(5);
            sparkle_step_384(6);
            sparkle_step_384(7);
            sparkle_step_384(8);
            sparkle_step_384(9);
            sparkle_step_384(10);
        }

        inline void schwaemm256_128::sparkle384_little()
        {
            sparkle_step_384(0);
            sparkle_step_384(1);
            sparkle_step_384(2);
            sparkle_step_384(3);
            sparkle_step_384(4);
            sparkle_step_384(5);
            sparkle_step_384(6);
        }

        inline void schwaemm256_128::absorb_encrypt(const unsigned char* in, unsigned char* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);

            if (out)
            {
                uint32_t* oi = reinterpret_cast<uint32_t*>(out);
                oi[0] = ii[0] ^ nonHHx[0];
                oi[1] = ii[1] ^ nonHHy[0];
                oi[2] = ii[2] ^ nonHHx[1];
                oi[3] = ii[3] ^ nonHHy[1];
                oi[4] = ii[4] ^ nonHHx[2];
                oi[5] = ii[5] ^ nonHHy[2];
                oi[6] = ii[6] ^ nonHHx[3];
                oi[7] = ii[7] ^ nonHHy[3];
            }

            uint32_t t = nonHHx[0];
            nonHHx[0] = nonHHx[2];
            nonHHx[2] ^= t;
            t = nonHHx[1];
            nonHHx[1] = nonHHx[3];
            nonHHx[3] ^= t;
            t = nonHHy[0];
            nonHHy[0] = nonHHy[2];
            nonHHy[2] ^= t;
            t = nonHHy[1];
            nonHHy[1] = nonHHy[3];
            nonHHy[3] ^= t;
            nonHHx[0] ^= ii[0] ^ nonHHx[4];
            nonHHy[0] ^= ii[1] ^ nonHHy[4];
            nonHHx[1] ^= ii[2] ^ nonHHx[5];
            nonHHy[1] ^= ii[3] ^ nonHHy[5];
            nonHHx[2] ^= ii[4] ^ nonHHx[4];
            nonHHy[2] ^= ii[5] ^ nonHHy[4];
            nonHHx[3] ^= ii[6] ^ nonHHx[5];
            nonHHy[3] ^= ii[7] ^ nonHHy[5];
        }

        inline void schwaemm256_128::absorb_decrypt(const unsigned char* in, unsigned char* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);

            uint32_t* oi = reinterpret_cast<uint32_t*>(out);
            oi[0] = ii[0] ^ nonHHx[0];
            oi[1] = ii[1] ^ nonHHy[0];
            oi[2] = ii[2] ^ nonHHx[1];
            oi[3] = ii[3] ^ nonHHy[1];
            oi[4] = ii[4] ^ nonHHx[2];
            oi[5] = ii[5] ^ nonHHy[2];
            oi[6] = ii[6] ^ nonHHx[3];
            oi[7] = ii[7] ^ nonHHy[3];

            uint32_t t = nonHHx[0];
            nonHHx[0] ^= nonHHx[2];
            nonHHx[2] = t;
            t = nonHHx[1];
            nonHHx[1] ^= nonHHx[3];
            nonHHx[3] = t;
            t = nonHHy[0];
            nonHHy[0] ^= nonHHy[2];
            nonHHy[2] = t;
            t = nonHHy[1];
            nonHHy[1] ^= nonHHy[3];
            nonHHy[3] = t;
            nonHHx[0] ^= ii[0] ^ nonHHx[4];
            nonHHy[0] ^= ii[1] ^ nonHHy[4];
            nonHHx[1] ^= ii[2] ^ nonHHx[5];
            nonHHy[1] ^= ii[3] ^ nonHHy[5];
            nonHHx[2] ^= ii[4] ^ nonHHx[4];
            nonHHy[2] ^= ii[5] ^ nonHHy[4];
            nonHHx[3] ^= ii[6] ^ nonHHx[5];
            nonHHy[3] ^= ii[7] ^ nonHHy[5];

        }

        inline void schwaemm256_128::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            const uint32_t* ni = reinterpret_cast<const uint32_t*>(nonce);
            nonHHx[0] = ni[0];
            nonHHy[0] = ni[1];
            nonHHx[1] = ni[2];
            nonHHy[1] = ni[3];
            nonHHx[2] = ni[4];
            nonHHy[2] = ni[5];
            nonHHx[3] = ni[6];
            nonHHy[3] = ni[7];
            nonHHx[4] = ki[0];
            nonHHy[4] = ki[1];
            nonHHx[5] = ki[2];
            nonHHy[5] = ki[3];
        }

        inline void schwaemm256_128::xor_key_to_state(const unsigned char* key)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            nonHHx[4] ^= ki[0];
            nonHHy[4] ^= ki[1];
            nonHHx[5] ^= ki[2];
            nonHHy[5] ^= ki[3];
        }

        void schwaemm256_128::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {

                nonHHy[5] ^= 0x4000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);

            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0x6000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                uint8_t outbuf[32];
                absorb_encrypt(buf, outbuf);
                memcpy(out, outbuf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x5000000);

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block, 0x7000000);

            xor_key_to_state(key);

            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                uint32_t* ic = reinterpret_cast<uint32_t*>(out);
                ic[0] = nonHHx[4];
                ic[1] = nonHHy[4];
                ic[2] = nonHHx[5];
                ic[3] = nonHHy[5];
            }
            else
            {
                uint32_t res[4];
                res[0] = nonHHx[4];
                res[1] = nonHHy[4];
                res[2] = nonHHx[5];
                res[3] = nonHHy[5];
                memcpy(out, res, tagsize_in_bytes());
                zero_memory(res, sizeof(res));
            }
            zero_memory(buf, sizeof(buf));
            clear();
        }

        bool schwaemm256_128::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;

            uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0x4000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0x6000000;

                uint32_t* oi = reinterpret_cast<uint32_t*>(buf);
                oi[0] = nonHHx[0];
                oi[1] = nonHHy[0];
                oi[2] = nonHHx[1];
                oi[3] = nonHHy[1];
                oi[4] = nonHHx[2];
                oi[5] = nonHHy[2];
                oi[6] = nonHHx[3];
                oi[7] = nonHHy[3];

                uint8_t outbuf[32];
                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;
                absorb_decrypt(buf, outbuf);
                memcpy(out, outbuf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x5000000);

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block, 0x7000000);

            xor_key_to_state(key);

            uint32_t res[4];
            res[0] = nonHHx[4];
            res[1] = nonHHy[4];
            res[2] = nonHHx[5];
            res[3] = nonHHy[5];
            zero_memory(buf, sizeof(buf));
            clear();

            bool result = tag_matches(reinterpret_cast<unsigned char*>(res), in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            zero_memory(res, sizeof(res));
            return result;
        }

        schwaemm256_256::schwaemm256_256()
        {
            clear();
        }

        schwaemm256_256::~schwaemm256_256()
        {
            clear();
        }

        void schwaemm256_256::clear()
        {
            memset(nonHHx, 0, sizeof(nonHHx));
            memset(nonHHy, 0, sizeof(nonHHy));
        }

        inline void schwaemm256_256::sparkle_step_common(int i)
        {
            nonHHy[0] ^= C[i % 8];
            nonHHy[1] ^= static_cast<uint32_t>(i);

            for (int r = 0; r < 8; r++)
            {
                nonHHx[r] += rotater32(nonHHy[r], 31);
                nonHHy[r] ^= rotater32(nonHHx[r], 24);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 17);
                nonHHy[r] ^= rotater32(nonHHx[r], 17);
                nonHHx[r] ^= C[r];
                nonHHx[r] += nonHHy[r];
                nonHHy[r] ^= rotater32(nonHHx[r], 31);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 24);
                nonHHy[r] ^= rotater32(nonHHx[r], 16);
                nonHHx[r] ^= C[r];
            }
        }

        inline void schwaemm256_256::sparkle_step_512(int i)
        {
            sparkle_step_common(i);

            uint32_t tx = nonHHx[0] ^ nonHHx[1] ^ nonHHx[2] ^ nonHHx[3];
            uint32_t ty = nonHHy[0] ^ nonHHy[1] ^ nonHHy[2] ^ nonHHy[3];
            tx = rotatel32(tx ^ (tx << 16), 16);
            ty = rotatel32(ty ^ (ty << 16), 16);

            nonHHx[4] ^= nonHHx[0] ^ ty;
            nonHHx[5] ^= nonHHx[1] ^ ty;
            nonHHx[6] ^= nonHHx[2] ^ ty;
            nonHHx[7] ^= nonHHx[3] ^ ty;
            nonHHy[4] ^= nonHHy[0] ^ tx;
            nonHHy[5] ^= nonHHy[1] ^ tx;
            nonHHy[6] ^= nonHHy[2] ^ tx;
            nonHHy[7] ^= nonHHy[3] ^ tx;

            tx = nonHHx[0];
            nonHHx[0] = nonHHx[5];
            nonHHx[5] = nonHHx[1];
            nonHHx[1] = nonHHx[6];
            nonHHx[6] = nonHHx[2];
            nonHHx[2] = nonHHx[7];
            nonHHx[7] = nonHHx[3];
            nonHHx[3] = nonHHx[4];
            nonHHx[4] = tx;

            ty = nonHHy[0];
            nonHHy[0] = nonHHy[5];
            nonHHy[5] = nonHHy[1];
            nonHHy[1] = nonHHy[6];
            nonHHy[6] = nonHHy[2];
            nonHHy[2] = nonHHy[7];
            nonHHy[7] = nonHHy[3];
            nonHHy[3] = nonHHy[4];
            nonHHy[4] = ty;

        }

        inline void schwaemm256_256::sparkle512_big()
        {
            sparkle_step_512(0);
            sparkle_step_512(1);
            sparkle_step_512(2);
            sparkle_step_512(3);
            sparkle_step_512(4);
            sparkle_step_512(5);
            sparkle_step_512(6);
            sparkle_step_512(7);
            sparkle_step_512(8);
            sparkle_step_512(9);
            sparkle_step_512(10);
            sparkle_step_512(11);
        }

        inline void schwaemm256_256::sparkle512_little()
        {
            sparkle_step_512(0);
            sparkle_step_512(1);
            sparkle_step_512(2);
            sparkle_step_512(3);
            sparkle_step_512(4);
            sparkle_step_512(5);
            sparkle_step_512(6);
            sparkle_step_512(7);
        }

        inline void schwaemm256_256::absorb_encrypt(const uint8_t* in, uint8_t* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);
            if (out)
            {
                uint32_t* oi = reinterpret_cast<uint32_t*>(out);
                oi[0] = ii[0] ^ nonHHx[0];
                oi[1] = ii[1] ^ nonHHy[0];
                oi[2] = ii[2] ^ nonHHx[1];
                oi[3] = ii[3] ^ nonHHy[1];
                oi[4] = ii[4] ^ nonHHx[2];
                oi[5] = ii[5] ^ nonHHy[2];
                oi[6] = ii[6] ^ nonHHx[3];
                oi[7] = ii[7] ^ nonHHy[3];

            }

            uint32_t t = nonHHx[0];
            nonHHx[0] = nonHHx[2];
            nonHHx[2] ^= t;
            t = nonHHx[1];
            nonHHx[1] = nonHHx[3];
            nonHHx[3] ^= t;
            t = nonHHy[0];
            nonHHy[0] = nonHHy[2];
            nonHHy[2] ^= t;
            t = nonHHy[1];
            nonHHy[1] = nonHHy[3];
            nonHHy[3] ^= t;

            nonHHx[0] ^= ii[0] ^ nonHHx[4];
            nonHHy[0] ^= ii[1] ^ nonHHy[4];
            nonHHx[1] ^= ii[2] ^ nonHHx[5];
            nonHHy[1] ^= ii[3] ^ nonHHy[5];
            nonHHx[2] ^= ii[4] ^ nonHHx[6];
            nonHHy[2] ^= ii[5] ^ nonHHy[6];
            nonHHx[3] ^= ii[6] ^ nonHHx[7];
            nonHHy[3] ^= ii[7] ^ nonHHy[7];
        }

        inline void schwaemm256_256::absorb_decrypt(const unsigned char* in, unsigned char* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);
            uint32_t* oi = reinterpret_cast<uint32_t*>(out);
            oi[0] = ii[0] ^ nonHHx[0];
            oi[1] = ii[1] ^ nonHHy[0];
            oi[2] = ii[2] ^ nonHHx[1];
            oi[3] = ii[3] ^ nonHHy[1];
            oi[4] = ii[4] ^ nonHHx[2];
            oi[5] = ii[5] ^ nonHHy[2];
            oi[6] = ii[6] ^ nonHHx[3];
            oi[7] = ii[7] ^ nonHHy[3];

            uint32_t t = nonHHx[0];
            nonHHx[0] ^= nonHHx[2];
            nonHHx[2] = t;
            t = nonHHx[1];
            nonHHx[1] ^= nonHHx[3];
            nonHHx[3] = t;
            t = nonHHy[0];
            nonHHy[0] ^= nonHHy[2];
            nonHHy[2] = t;
            t = nonHHy[1];
            nonHHy[1] ^= nonHHy[3];
            nonHHy[3] = t;

            nonHHx[0] ^= ii[0] ^ nonHHx[4];
            nonHHy[0] ^= ii[1] ^ nonHHy[4];
            nonHHx[1] ^= ii[2] ^ nonHHx[5];
            nonHHy[1] ^= ii[3] ^ nonHHy[5];
            nonHHx[2] ^= ii[4] ^ nonHHx[6];
            nonHHy[2] ^= ii[5] ^ nonHHy[6];
            nonHHx[3] ^= ii[6] ^ nonHHx[7];
            nonHHy[3] ^= ii[7] ^ nonHHy[7];
        }

        inline void schwaemm256_256::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            const uint32_t* ni = reinterpret_cast<const uint32_t*>(nonce);
            nonHHx[0] = ni[0];
            nonHHy[0] = ni[1];
            nonHHx[1] = ni[2];
            nonHHy[1] = ni[3];
            nonHHx[2] = ni[4];
            nonHHy[2] = ni[5];
            nonHHx[3] = ni[6];
            nonHHy[3] = ni[7];
            nonHHx[4] = ki[0];
            nonHHy[4] = ki[1];
            nonHHx[5] = ki[2];
            nonHHy[5] = ki[3];
            nonHHx[6] = ki[4];
            nonHHy[6] = ki[5];
            nonHHx[7] = ki[6];
            nonHHy[7] = ki[7];

        }

        inline void schwaemm256_256::xor_key_to_state(const unsigned char* key)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            nonHHx[4] ^= ki[0];
            nonHHy[4] ^= ki[1];
            nonHHx[5] ^= ki[2];
            nonHHy[5] ^= ki[3];
            nonHHx[6] ^= ki[4];
            nonHHy[6] ^= ki[5];
            nonHHx[7] ^= ki[6];
            nonHHy[7] ^= ki[7];
        }

        void schwaemm256_256::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[7] ^= 0x10000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[7] ^= 0x12000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                uint8_t bufout[32];
                absorb_encrypt(buf, bufout);
                memcpy(out, bufout, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle512_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x11000000);

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block, 0x13000000);

            xor_key_to_state(key);

            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                uint32_t* ic = reinterpret_cast<uint32_t*>(out);
                ic[0] = nonHHx[4];
                ic[1] = nonHHy[4];
                ic[2] = nonHHx[5];
                ic[3] = nonHHy[5];
                ic[4] = nonHHx[6];
                ic[5] = nonHHy[6];
                ic[6] = nonHHx[7];
                ic[7] = nonHHy[7];
            }
            else
            {
                uint32_t res[8];
                res[0] = nonHHx[4];
                res[1] = nonHHy[4];
                res[2] = nonHHx[5];
                res[3] = nonHHy[5];
                res[4] = nonHHx[6];
                res[5] = nonHHy[6];
                res[6] = nonHHx[7];
                res[7] = nonHHy[7];
                memcpy(out, res, tagsize_in_bytes());
                zero_memory(res, sizeof(res));
            }
            zero_memory(buf, sizeof(buf));
            clear();
        }

        bool schwaemm256_256::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;

            uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[7] ^= 0x10000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[7] ^= 0x12000000;
                uint32_t* oi = reinterpret_cast<uint32_t*>(buf);
                oi[0] = nonHHx[0];
                oi[1] = nonHHy[0];
                oi[2] = nonHHx[1];
                oi[3] = nonHHy[1];
                oi[4] = nonHHx[2];
                oi[5] = nonHHy[2];
                oi[6] = nonHHx[3];
                oi[7] = nonHHy[3];

                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;
                uint8_t bufout[32];
                absorb_decrypt(buf, bufout);
                memcpy(out, bufout, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle512_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x11000000);

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block, 0x13000000);

            xor_key_to_state(key);

            uint32_t res[8];
            res[0] = nonHHx[4];
            res[1] = nonHHy[4];
            res[2] = nonHHx[5];
            res[3] = nonHHy[5];
            res[4] = nonHHx[6];
            res[5] = nonHHy[6];
            res[6] = nonHHx[7];
            res[7] = nonHHy[7];
            zero_memory(buf, sizeof(buf));
            clear();

            bool result = tag_matches(reinterpret_cast<unsigned char*>(res), in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            zero_memory(res, sizeof(res));
            return result;
        }

        schwaemm192_192::schwaemm192_192()
        {
            clear();
        }

        schwaemm192_192::~schwaemm192_192()
        {
            clear();
        }

        void schwaemm192_192::clear()
        {
            memset(nonHHx, 0, sizeof(nonHHx));
            memset(nonHHy, 0, sizeof(nonHHy));
        }

        inline void schwaemm192_192::sparkle_step_common(int i)
        {
            nonHHy[0] ^= C[i % 8];
            nonHHy[1] ^= static_cast<uint32_t>(i);

            for (int r = 0; r < 6; r++)
            {
                nonHHx[r] += rotater32(nonHHy[r], 31);
                nonHHy[r] ^= rotater32(nonHHx[r], 24);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 17);
                nonHHy[r] ^= rotater32(nonHHx[r], 17);
                nonHHx[r] ^= C[r];
                nonHHx[r] += nonHHy[r];
                nonHHy[r] ^= rotater32(nonHHx[r], 31);
                nonHHx[r] ^= C[r];
                nonHHx[r] += rotater32(nonHHy[r], 24);
                nonHHy[r] ^= rotater32(nonHHx[r], 16);
                nonHHx[r] ^= C[r];
            }
        }

        inline void schwaemm192_192::sparkle_step_384(int i)
        {
            sparkle_step_common(i);

            uint32_t tx = nonHHx[0] ^ nonHHx[1] ^ nonHHx[2];
            uint32_t ty = nonHHy[0] ^ nonHHy[1] ^ nonHHy[2];
            tx = rotatel32(tx ^ (tx << 16), 16);
            ty = rotatel32(ty ^ (ty << 16), 16);

            nonHHx[3] ^= nonHHx[0] ^ ty;
            nonHHx[4] ^= nonHHx[1] ^ ty;
            nonHHx[5] ^= nonHHx[2] ^ ty;
            nonHHy[3] ^= nonHHy[0] ^ tx;
            nonHHy[4] ^= nonHHy[1] ^ tx;
            nonHHy[5] ^= nonHHy[2] ^ tx;

            tx = nonHHx[0];
            nonHHx[0] = nonHHx[4];
            nonHHx[4] = nonHHx[1];
            nonHHx[1] = nonHHx[5];
            nonHHx[5] = nonHHx[2];
            nonHHx[2] = nonHHx[3];
            nonHHx[3] = tx;

            ty = nonHHy[0];
            nonHHy[0] = nonHHy[4];
            nonHHy[4] = nonHHy[1];
            nonHHy[1] = nonHHy[5];
            nonHHy[5] = nonHHy[2];
            nonHHy[2] = nonHHy[3];
            nonHHy[3] = ty;
        }


        inline void schwaemm192_192::sparkle384_big()
        {
            sparkle_step_384(0);
            sparkle_step_384(1);
            sparkle_step_384(2);
            sparkle_step_384(3);
            sparkle_step_384(4);
            sparkle_step_384(5);
            sparkle_step_384(6);
            sparkle_step_384(7);
            sparkle_step_384(8);
            sparkle_step_384(9);
            sparkle_step_384(10);
        }

        inline void schwaemm192_192::sparkle384_little()
        {
            sparkle_step_384(0);
            sparkle_step_384(1);
            sparkle_step_384(2);
            sparkle_step_384(3);
            sparkle_step_384(4);
            sparkle_step_384(5);
            sparkle_step_384(6);
        }
        inline void schwaemm192_192::absorb_encrypt(const unsigned char* in, unsigned char* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);

            if (out)
            {
                uint32_t* oi = reinterpret_cast<uint32_t*>(out);
                oi[0] = ii[0] ^ nonHHx[0];
                oi[1] = ii[1] ^ nonHHy[0];
                oi[2] = ii[2] ^ nonHHx[1];
                oi[3] = ii[3] ^ nonHHy[1];
                oi[4] = ii[4] ^ nonHHx[2];
                oi[5] = ii[5] ^ nonHHy[2];
            }

            uint32_t t = nonHHx[0];
            nonHHx[0] = nonHHy[1];
            nonHHy[1] ^= t;

            t = nonHHy[0];
            nonHHy[0] = nonHHx[2];
            nonHHx[2] ^= t;

            t = nonHHx[1];
            nonHHx[1] = nonHHy[2];
            nonHHy[2] ^= t;

            nonHHx[0] ^= ii[0] ^ nonHHx[3];
            nonHHy[0] ^= ii[1] ^ nonHHy[3];
            nonHHx[1] ^= ii[2] ^ nonHHx[4];
            nonHHy[1] ^= ii[3] ^ nonHHy[4];
            nonHHx[2] ^= ii[4] ^ nonHHx[5];
            nonHHy[2] ^= ii[5] ^ nonHHy[5];
        }

        inline void schwaemm192_192::absorb_decrypt(const uint8_t* in, uint8_t* out)
        {
            const uint32_t* ii = reinterpret_cast<const uint32_t*>(in);

            uint32_t* oi = reinterpret_cast<uint32_t*>(out);
            oi[0] = ii[0] ^ nonHHx[0];
            oi[1] = ii[1] ^ nonHHy[0];
            oi[2] = ii[2] ^ nonHHx[1];
            oi[3] = ii[3] ^ nonHHy[1];
            oi[4] = ii[4] ^ nonHHx[2];
            oi[5] = ii[5] ^ nonHHy[2];

            uint32_t t = nonHHx[0];
            nonHHx[0] ^= nonHHy[1];
            nonHHy[1] = t;
            t = nonHHy[0];
            nonHHy[0] ^= nonHHx[2];
            nonHHx[2] = t;
            t = nonHHx[1];
            nonHHx[1] ^= nonHHy[2];
            nonHHy[2] = t;

            nonHHx[0] ^= ii[0] ^ nonHHx[3];
            nonHHy[0] ^= ii[1] ^ nonHHy[3];
            nonHHx[1] ^= ii[2] ^ nonHHx[4];
            nonHHy[1] ^= ii[3] ^ nonHHy[4];
            nonHHx[2] ^= ii[4] ^ nonHHx[5];
            nonHHy[2] ^= ii[5] ^ nonHHy[5];

        }

        inline void schwaemm192_192::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            const uint32_t* ni = reinterpret_cast<const uint32_t*>(nonce);
            nonHHx[0] = ni[0];
            nonHHy[0] = ni[1];
            nonHHx[1] = ni[2];
            nonHHy[1] = ni[3];
            nonHHx[2] = ni[4];
            nonHHy[2] = ni[5];
            nonHHx[3] = ki[0];
            nonHHy[3] = ki[1];
            nonHHx[4] = ki[2];
            nonHHy[4] = ki[3];
            nonHHx[5] = ki[4];
            nonHHy[5] = ki[5];

        }

        inline void schwaemm192_192::xor_key_to_state(const unsigned char* key)
        {
            const uint32_t* ki = reinterpret_cast<const uint32_t*>(key);
            nonHHx[3] ^= ki[0];
            nonHHy[3] ^= ki[1];
            nonHHx[4] ^= ki[2];
            nonHHy[4] ^= ki[3];
            nonHHx[5] ^= ki[4];
            nonHHy[5] ^= ki[5];

        }

        void schwaemm192_192::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 24; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0x8000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0xA000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                uint8_t bufout[32];
                absorb_encrypt(buf, bufout);
                memcpy(out, bufout, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x9000000);

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block, 0xB000000);

            xor_key_to_state(key);

            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                uint32_t* ic = reinterpret_cast<uint32_t*>(out);
                ic[0] = nonHHx[3];
                ic[1] = nonHHy[3];
                ic[2] = nonHHx[4];
                ic[3] = nonHHy[4];
                ic[4] = nonHHx[5];
                ic[5] = nonHHy[5];
            }
            else
            {
                uint32_t res[6];
                res[0] = nonHHx[3];
                res[1] = nonHHy[3];
                res[2] = nonHHx[4];
                res[3] = nonHHy[4];
                res[4] = nonHHx[5];
                res[5] = nonHHy[5];
                memcpy(out, res, tagsize_in_bytes());
                zero_memory(res, sizeof(res));
            }
            zero_memory(buf, sizeof(buf));
            clear();
        }

        bool schwaemm192_192::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;

            uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 24; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0x8000000;
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                nonHHy[5] ^= 0xA000000;

                uint32_t* oi = reinterpret_cast<uint32_t*>(buf);
                oi[0] = nonHHx[0];
                oi[1] = nonHHy[0];
                oi[2] = nonHHx[1];
                oi[3] = nonHHy[1];
                oi[4] = nonHHx[2];
                oi[5] = nonHHy[2];
                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;

                uint8_t bufout[32];
                absorb_decrypt(buf, bufout);
                memcpy(out, bufout, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 0x9000000);

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block, 0xB000000);

            xor_key_to_state(key);

            uint32_t res[6];
            res[0] = nonHHx[3];
            res[1] = nonHHy[3];
            res[2] = nonHHx[4];
            res[3] = nonHHy[4];
            res[4] = nonHHx[5];
            res[5] = nonHHy[5];
            zero_memory(buf, sizeof(buf));
            clear();

            bool result = tag_matches(reinterpret_cast<unsigned char*>(res), in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            zero_memory(res, sizeof(res));
            return result;
        }

    }
}

