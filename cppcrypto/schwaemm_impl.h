/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_AEAD_SCHWAEMM_IMPL_H
#define CPPCRYPTO_AEAD_SCHWAEMM_IMPL_H

#include "block_cipher.h"
#include <memory>
#include <stdexcept>
#include <vector>
#include <bitset>
#include <array>

namespace cppcrypto
{
    namespace detail
    {
        class schwaemm_impl
        {
        public:
            virtual ~schwaemm_impl() {}

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) = 0;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) = 0;

            virtual void set_tagsize_in_bits(size_t tagsize);

            virtual size_t ivsize_in_bytes() const = 0;
            virtual size_t keysize_in_bytes() const = 0;
            virtual size_t tagsize_in_bytes_default() const = 0;

            virtual size_t tagsize_in_bytes() const;

        protected:
            size_t tagsize_in_bits = SIZE_MAX;
        };

        class schwaemm256_128 : public schwaemm_impl
        {
        public:
            schwaemm256_128();
            ~schwaemm256_128();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            void clear();

        private:
            template<typename T, typename U>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, uint32_t constant)
            {
                if (!length)
                    return;
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
                    nonHHy[5] ^= constant;
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

            void sparkle_step_common(int i);

            void sparkle_step_384(int i);

            virtual size_t ivsize_in_bytes() const override { return 32; }
            virtual size_t keysize_in_bytes() const override { return 16; }
            virtual size_t tagsize_in_bytes_default() const override { return 16; }

            uint32_t nonHHx[6];
            uint32_t nonHHy[6];
        };


        class schwaemm256_256 : public schwaemm_impl
        {
        public:
            schwaemm256_256();
            ~schwaemm256_256();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            void clear();

        private:
            template<typename T, typename U>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, uint32_t constant)
            {
                if (!length)
                    return;
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
                    nonHHy[7] ^= constant;
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

            void sparkle_step_common(int i);

            void sparkle_step_512(int i);

            virtual size_t ivsize_in_bytes() const override { return 32; }
            virtual size_t keysize_in_bytes() const override { return 32; }
            virtual size_t tagsize_in_bytes_default() const override { return 32; }

            uint32_t nonHHx[8];
            uint32_t nonHHy[8];
        };

        class schwaemm192_192 : public schwaemm_impl
        {
        public:
            schwaemm192_192();
            ~schwaemm192_192();

            virtual void encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;
            virtual bool decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out) override;

            void clear();

        private:
            template<typename T, typename U>
            void transform_blocks(const unsigned char* in, unsigned long long length, T func_encrypt, U incomplete_lastblock, uint32_t constant)
            {
                if (!length)
                    return;
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
                    nonHHy[5] ^= constant;
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

            void sparkle_step_common(int i);

            void sparkle_step_384(int i);

            virtual size_t ivsize_in_bytes() const override { return 24; }
            virtual size_t keysize_in_bytes() const override { return 24; }
            virtual size_t tagsize_in_bytes_default() const override { return 24; }

            uint32_t nonHHx[6];
            uint32_t nonHHy[6];
        };


    }
}

#endif
