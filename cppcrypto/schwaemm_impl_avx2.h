/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_SCHWAEMM_AVX2_IMPL_H
#define CPPCRYPTO_AEAD_SCHWAEMM_AVX2_IMPL_H

#include "schwaemm_impl.h"
#include <immintrin.h>

namespace cppcrypto
{
    namespace detail
    {

        class schwaemm256_256_avx2 : public schwaemm_impl
        {
        public:
            schwaemm256_256_avx2();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            virtual size_t ivsize_in_bytes() const override { return 32; }
            virtual size_t keysize_in_bytes() const override { return 32; }
            virtual size_t tagsize_in_bytes_default() const override { return 32; }

        private:
            template<typename T, typename U, typename V>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, V add_constant)
            {
                auto blocks = (length - 1) / 32;
                for (unsigned long long blk = 0; blk < blocks; blk++)
                {
                    func_encrypt(in);
                    sparkle512_little();
                    in += 32;
                    length -= 32;
                }

                if (length < 32)
                    incomplete_lastblock(in, length);
                else
                {
                    add_constant();
                    func_encrypt(in);
                }
                sparkle512_big();
            }

            void set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce);

            void xor_key_to_state(const unsigned char* key);

            void absorb_encrypt(const unsigned char* in, unsigned char* out);

            void absorb_decrypt(const uint8_t* in, uint8_t* out);

            void sparkle512_big();

            void sparkle512_little();

            void sparkle_step_common(int i, __m256i& Hx, __m256i& Hy);

            void sparkle_step_512(int i, __m256i& Hx, __m256i& Hy);

            __m256i HHx;
            __m256i HHy;

            const __m256i Hc;
            const __m128i r16_128;
            const __m256i r16_256;
            const __m256i mask3;
            const __m256i mask4;
            const __m256i mask5;
        };

        class schwaemm256_128_avx2 : public schwaemm_impl
        {
        public:
            schwaemm256_128_avx2();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            virtual size_t ivsize_in_bytes() const override { return 32; }
            virtual size_t keysize_in_bytes() const override { return 16; }
            virtual size_t tagsize_in_bytes_default() const override { return 16; }

        private:
            template<typename T, typename U, typename V>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, V add_constant)
            {
                auto blocks = (length - 1) / 32;
                for (unsigned long long blk = 0; blk < blocks; blk++)
                {
                    func_encrypt(in);
                    sparkle384_little();
                    in += 32;
                    length -= 32;
                }

                if (length < 32)
                    incomplete_lastblock(in, length);
                else
                {
                    add_constant();
                    func_encrypt(in);
                }
                sparkle384_big();
            }

            void set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce);

            void xor_key_to_state(const unsigned char* key);

            void absorb_encrypt(const unsigned char* in, unsigned char* out);

            void absorb_decrypt(const uint8_t* in, uint8_t* out);

            void sparkle384_big();

            void sparkle384_little();

            void sparkle_step_common(int i, __m256i& Hx, __m256i& Hy);

            void sparkle_step_384(int i, __m256i& Hx, __m256i& Hy);

            __m256i HHx;
            __m256i HHy;

            const __m256i Hc;
            const __m128i r16_128;
            const __m256i r16_256;
            const __m256i mask1;
            const __m256i mask2;
            const __m256i mask3;
            const __m256i mask4;
        };

        class schwaemm192_192_avx2 : public schwaemm_impl
        {
        public:
            schwaemm192_192_avx2();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            virtual size_t ivsize_in_bytes() const override { return 24; }
            virtual size_t keysize_in_bytes() const override { return 24; }
            virtual size_t tagsize_in_bytes_default() const override { return 24; }

        private:
            template<typename T, typename U, typename V>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, V add_constant)
            {
                auto blocks = (length - 1) / 24;
                for (unsigned long long blk = 0; blk < blocks; blk++)
                {
                    func_encrypt(in);
                    sparkle384_little();
                    in += 24;
                    length -= 24;
                }

                if (length < 24)
                    incomplete_lastblock(in, length);
                else
                {
                    add_constant();
                    func_encrypt(in);
                }
                sparkle384_big();
            }

            void set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce);

            void xor_key_to_state(const unsigned char* key);

            void absorb_encrypt(const unsigned char* in, unsigned char* out);

            void absorb_decrypt(const uint8_t* in, uint8_t* out);

            void sparkle384_big();

            void sparkle384_little();

            void sparkle_step_common(int i, __m256i& Hx, __m256i& Hy);

            void sparkle_step_384(int i, __m256i& Hx, __m256i& Hy);

            __m256i HHx;
            __m256i HHy;

            const __m256i Hc;
            const __m128i r16_128;
            const __m256i r16_256;
            const __m256i mask1;
            const __m256i mask2;
            const __m256i mask3;
            const __m256i mask4;
            const __m256i mask5;
            const __m256i mask6;
        };

    }
}

#endif
