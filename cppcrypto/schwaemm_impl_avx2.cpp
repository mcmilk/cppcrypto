/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "schwaemm_impl_avx2.h"
#include "portability.h"
#include "functions.h"
#include <emmintrin.h>
#include <smmintrin.h>
#include <xmmintrin.h>
#include <immintrin.h>
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

            inline __m128i hxor_epi32_avx(__m128i x)
            {
                __m128i sum64 = _mm_xor_si128(_mm_shuffle_epi32(x, 0b01001110), x);
                __m128i sum32 = _mm_xor_si128(sum64, _mm_shuffle_epi32(sum64, 0b10110001));
                return sum32;
            }

            inline __m128i hxor3_epi32_avx(__m128i x)
            {
                __m128i t = _mm_blend_epi32(_mm_setzero_si128(), x, 0b0111);
                return hxor_epi32_avx(t);
            }

        }

        schwaemm256_256_avx2::schwaemm256_256_avx2()
            : HHx(_mm256_setzero_si256())
            , HHy(_mm256_setzero_si256())
            , Hc(_mm256_loadu_si256((const __m256i*) C))
            , r16_128(_mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , r16_256(_mm256_set_epi8(29, 28, 31, 30, 25, 24, 27, 26, 21, 20, 23, 22, 17, 16, 19, 18, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , mask3(_mm256_set_epi32(3, 3, 2, 2, 1, 1, 0, 0))
            , mask4(_mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0))
            , mask5(_mm256_set_epi32(7, 7, 6, 6, 5, 5, 4, 4))
        {
        }

        inline void schwaemm256_256_avx2::sparkle_step_common(int i, __m256i& Hx, __m256i& Hy)
        {
            Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, i, C[i % 8]));
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 31), _mm256_slli_epi32(Hy, 32 - 31)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 24), _mm256_slli_epi32(Hx, 32 - 24)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 17), _mm256_slli_epi32(Hy, 32 - 17)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 17), _mm256_slli_epi32(Hx, 32 - 17)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, Hy);
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 31), _mm256_slli_epi32(Hx, 32 - 31)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 24), _mm256_slli_epi32(Hy, 32 - 24)));
            Hy = _mm256_xor_si256(Hy, _mm256_shuffle_epi8(Hx, r16_256));
            Hx = _mm256_xor_si256(Hx, Hc);
        }

        inline void schwaemm256_256_avx2::sparkle_step_512(int i, __m256i& Hx, __m256i& Hy)
        {
            sparkle_step_common(i, Hx, Hy);
            __m128i xa = hxor_epi32_avx(_mm256_castsi256_si128(Hx));
            __m128i ya = hxor_epi32_avx(_mm256_castsi256_si128(Hy));
            xa = _mm_shuffle_epi8(_mm_xor_si128(xa, _mm_slli_epi32(xa, 16)), r16_128);
            ya = _mm_shuffle_epi8(_mm_xor_si128(ya, _mm_slli_epi32(ya, 16)), r16_128);
            Hx = _mm256_set_m128i(_mm256_castsi256_si128(Hx), _mm_shuffle_epi32(_mm_xor_si128(ya, _mm_xor_si128(_mm256_castsi256_si128(Hx), _mm256_extracti128_si256(Hx, 1))), 0b00111001));
            Hy = _mm256_set_m128i(_mm256_castsi256_si128(Hy), _mm_shuffle_epi32(_mm_xor_si128(xa, _mm_xor_si128(_mm256_castsi256_si128(Hy), _mm256_extracti128_si256(Hy, 1))), 0b00111001));
        }

        inline void schwaemm256_256_avx2::sparkle512_big()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_512(0, Hx, Hy);
            sparkle_step_512(1, Hx, Hy);
            sparkle_step_512(2, Hx, Hy);
            sparkle_step_512(3, Hx, Hy);
            sparkle_step_512(4, Hx, Hy);
            sparkle_step_512(5, Hx, Hy);
            sparkle_step_512(6, Hx, Hy);
            sparkle_step_512(7, Hx, Hy);
            sparkle_step_512(8, Hx, Hy);
            sparkle_step_512(9, Hx, Hy);
            sparkle_step_512(10, Hx, Hy);
            sparkle_step_512(11, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm256_256_avx2::sparkle512_little()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_512(0, Hx, Hy);
            sparkle_step_512(1, Hx, Hy);
            sparkle_step_512(2, Hx, Hy);
            sparkle_step_512(3, Hx, Hy);
            sparkle_step_512(4, Hx, Hy);
            sparkle_step_512(5, Hx, Hy);
            sparkle_step_512(6, Hx, Hy);
            sparkle_step_512(7, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm256_256_avx2::absorb_encrypt(const uint8_t* in, uint8_t* out)
        {
            __m256i in256 = _mm256_loadu_si256((const __m256i*) in);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            if (out)
                _mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010)));

            __m128i x1 = _mm256_castsi256_si128(HHx);
            __m128i xt = _mm_xor_si128(_mm_unpackhi_epi64(x1, x1), _mm_unpacklo_epi64(_mm_setzero_si128(), x1));
            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), _mm_xor_si128(_mm_xor_si128(xt, _mm256_extracti128_si256(HHx, 1)), _mm256_castsi256_si128(inr)));

            __m128i y1 = _mm256_castsi256_si128(HHy);
            __m128i yt = _mm_xor_si128(_mm_unpackhi_epi64(y1, y1), _mm_unpacklo_epi64(_mm_setzero_si128(), y1));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), _mm_xor_si128(_mm_xor_si128(yt, _mm256_extracti128_si256(HHy, 1)), _mm256_extracti128_si256(inr, 1)));
        }

        inline void schwaemm256_256_avx2::absorb_decrypt(const unsigned char* in, unsigned char* out)
        {
            __m256i in256 = _mm256_loadu_si256((const __m256i*) in);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            _mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010)));

            __m128i x1 = _mm256_castsi256_si128(HHx);
            __m128i xt = _mm_xor_si128(_mm_shuffle_epi32(x1, 0b01001110), _mm_unpacklo_epi64(x1, _mm_setzero_si128()));
            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), _mm_xor_si128(_mm_xor_si128(xt, _mm256_extracti128_si256(HHx, 1)), _mm256_castsi256_si128(inr)));

            __m128i y1 = _mm256_castsi256_si128(HHy);
            __m128i yt = _mm_xor_si128(_mm_shuffle_epi32(y1, 0b01001110), _mm_unpacklo_epi64(y1, _mm_setzero_si128()));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), _mm_xor_si128(_mm_xor_si128(yt, _mm256_extracti128_si256(HHy, 1)), _mm256_extracti128_si256(inr, 1)));
        }

        inline void schwaemm256_256_avx2::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            __m256i noncet = _mm256_permutevar8x32_epi32(_mm256_loadu_si256((const __m256i*) nonce), mask4);
            __m256i keyt = _mm256_permutevar8x32_epi32(_mm256_loadu_si256((const __m256i*) key), mask4);

            HHx = _mm256_set_m128i(_mm256_castsi256_si128(keyt), _mm256_castsi256_si128(noncet));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(keyt, 1), _mm256_extracti128_si256(noncet, 1));
        }

        inline void schwaemm256_256_avx2::xor_key_to_state(const unsigned char* key)
        {
            __m256i inr = _mm256_permutevar8x32_epi32(_mm256_loadu_si256((const __m256i*) key), mask4);

            HHx = _mm256_xor_si256(HHx, _mm256_set_m128i(_mm256_castsi256_si128(inr), _mm_setzero_si128()));
            HHy = _mm256_xor_si256(HHy, _mm256_set_m128i(_mm256_extracti128_si256(inr, 1), _mm_setzero_si128()));
        }


        void schwaemm256_256_avx2::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            alignas(32) uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x10000000, 0, 0, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x12000000, 0, 0, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle512_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad, 
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x11000000, 0, 0, 0, 0, 0, 0, 0)); });

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x13000000, 0, 0, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);

            if (tagsize_in_bytes() == tagsize_in_bytes_default())
                _mm256_storeu_si256((__m256i*) out, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010));
            else
            {
                _mm256_storeu_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010));
                memcpy(out, buf, tagsize_in_bytes());
            }
        }

        bool schwaemm256_256_avx2::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;
            alignas(32) uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x10000000, 0, 0, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x12000000, 0, 0, 0, 0, 0, 0, 0));
                _mm256_store_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010));

                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;
                absorb_decrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle512_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x11000000, 0, 0, 0, 0, 0, 0, 0)); });

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0x13000000, 0, 0, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);

            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                __m256i res = _mm256_xor_si256(_mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010), _mm256_loadu_si256((__m256i*)(in + inlen - 32)));
                int result = _mm256_testz_si256(res, res) - 1;
                return !result;
            }
            else
            {
                _mm256_store_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010));
                return tag_matches(buf, in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            }
        }

        schwaemm256_128_avx2::schwaemm256_128_avx2()
            : HHx(_mm256_setzero_si256())
            , HHy(_mm256_setzero_si256())
            , Hc(_mm256_loadu_si256((const __m256i*) C))
            , r16_128(_mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , r16_256(_mm256_set_epi8(29, 28, 31, 30, 25, 24, 27, 26, 21, 20, 23, 22, 17, 16, 19, 18, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , mask1(_mm256_setr_epi32(7, 7, 7, 0, 1, 2, 7, 7))
            , mask2(_mm256_set_epi32(7, 6, 2, 1, 0, 3, 5, 4))
            , mask3(_mm256_set_epi32(3, 3, 2, 2, 1, 1, 0, 0))
            , mask4(_mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0))
        {
        }

        inline void schwaemm256_128_avx2::sparkle_step_common(int i, __m256i& Hx, __m256i& Hy)
        {
            Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, i, C[i % 8]));
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 31), _mm256_slli_epi32(Hy, 32 - 31)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 24), _mm256_slli_epi32(Hx, 32 - 24)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 17), _mm256_slli_epi32(Hy, 32 - 17)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 17), _mm256_slli_epi32(Hx, 32 - 17)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, Hy);
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 31), _mm256_slli_epi32(Hx, 32 - 31)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 24), _mm256_slli_epi32(Hy, 32 - 24)));
            Hy = _mm256_xor_si256(Hy, _mm256_shuffle_epi8(Hx, r16_256));
            Hx = _mm256_xor_si256(Hx, Hc);
        }

        inline void schwaemm256_128_avx2::sparkle_step_384(int i, __m256i& Hx, __m256i& Hy)
        {
            sparkle_step_common(i, Hx, Hy);
            Hx = _mm256_blend_epi32(_mm256_setzero_si256(), Hx, 0b00111111);
            Hy = _mm256_blend_epi32(_mm256_setzero_si256(), Hy, 0b00111111);
            __m128i xa = hxor3_epi32_avx(_mm256_castsi256_si128(Hx));
            __m128i ya = hxor3_epi32_avx(_mm256_castsi256_si128(Hy));
            xa = _mm_shuffle_epi8(_mm_xor_si128(xa, _mm_slli_epi32(xa, 16)), r16_128);
            ya = _mm_shuffle_epi8(_mm_xor_si128(ya, _mm_slli_epi32(ya, 16)), r16_128);
            Hx = _mm256_blend_epi32(Hx, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hx, mask1), Hx), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(ya), mask1)), 0b00111000);
            Hy = _mm256_blend_epi32(Hy, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hy, mask1), Hy), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(xa), mask1)), 0b00111000);
            Hx = _mm256_permutevar8x32_epi32(Hx, mask2);
            Hy = _mm256_permutevar8x32_epi32(Hy, mask2);
        }

        inline void schwaemm256_128_avx2::sparkle384_big()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_384(0, Hx, Hy);
            sparkle_step_384(1, Hx, Hy);
            sparkle_step_384(2, Hx, Hy);
            sparkle_step_384(3, Hx, Hy);
            sparkle_step_384(4, Hx, Hy);
            sparkle_step_384(5, Hx, Hy);
            sparkle_step_384(6, Hx, Hy);
            sparkle_step_384(7, Hx, Hy);
            sparkle_step_384(8, Hx, Hy);
            sparkle_step_384(9, Hx, Hy);
            sparkle_step_384(10, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm256_128_avx2::sparkle384_little()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_384(0, Hx, Hy);
            sparkle_step_384(1, Hx, Hy);
            sparkle_step_384(2, Hx, Hy);
            sparkle_step_384(3, Hx, Hy);
            sparkle_step_384(4, Hx, Hy);
            sparkle_step_384(5, Hx, Hy);
            sparkle_step_384(6, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm256_128_avx2::absorb_encrypt(const unsigned char* in, unsigned char* out)
        {
            __m256i in256 = _mm256_loadu_si256((const __m256i*) in);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            if (out)
            {
                __m256i h = _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010));
                _mm256_storeu_si256((__m256i*) out, h);
            }

            __m128i x1 = _mm256_castsi256_si128(HHx);
            __m128i xt = _mm256_extracti128_si256(HHx, 1);
            xt = _mm_xor_si128(_mm_xor_si128(_mm_unpackhi_epi64(x1, x1), _mm_unpacklo_epi64(_mm_setzero_si128(), x1)), _mm_unpacklo_epi64(xt, xt));
            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), _mm_xor_si128(xt, _mm256_castsi256_si128(inr)));

            __m128i y1 = _mm256_castsi256_si128(HHy);
            __m128i yt = _mm256_extracti128_si256(HHy, 1);
            yt = _mm_xor_si128(_mm_xor_si128(_mm_unpackhi_epi64(y1, y1), _mm_unpacklo_epi64(_mm_setzero_si128(), y1)), _mm_unpacklo_epi64(yt, yt));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), _mm_xor_si128(yt, _mm256_extracti128_si256(inr, 1)));
        }

        inline void schwaemm256_128_avx2::absorb_decrypt(const unsigned char* in, unsigned char* out)
        {
            __m256i in256 = _mm256_loadu_si256((const __m256i*) in);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            _mm256_storeu_si256((__m256i*) out, _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010)));

            __m128i x1 = _mm256_castsi256_si128(HHx);
            __m128i xt = _mm256_extracti128_si256(HHx, 1);
            xt = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi32(x1, 0b01001110), _mm_unpacklo_epi64(x1, _mm_setzero_si128())), _mm_unpacklo_epi64(xt, xt)), _mm256_castsi256_si128(inr));
            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), xt);

            __m128i y1 = _mm256_castsi256_si128(HHy);
            __m128i yt = _mm256_extracti128_si256(HHy, 1);
            yt = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi32(y1, 0b01001110), _mm_unpacklo_epi64(y1, _mm_setzero_si128())), _mm_unpacklo_epi64(yt, yt));
            yt = _mm_xor_si128(yt, _mm256_extracti128_si256(inr, 1));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), yt);
        }

        inline void schwaemm256_128_avx2::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            __m256i noncet = _mm256_permutevar8x32_epi32(_mm256_loadu_si256((const __m256i*) nonce), mask4);
            __m128i key128 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*) key), 0b11011000);

            HHx = _mm256_set_m128i(_mm_unpacklo_epi64(key128, _mm_setzero_si128()), _mm256_castsi256_si128(noncet));
            HHy = _mm256_set_m128i(_mm_unpackhi_epi64(key128, _mm_setzero_si128()), _mm256_extracti128_si256(noncet, 1));
        }

        inline void schwaemm256_128_avx2::xor_key_to_state(const unsigned char* key)
        {
            __m128i key128 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*) key), 0b11011000);

            HHx = _mm256_xor_si256(HHx, _mm256_set_m128i(_mm_unpacklo_epi64(key128, _mm_setzero_si128()), _mm_setzero_si128()));
            HHy = _mm256_xor_si256(HHy, _mm256_set_m128i(_mm_unpackhi_epi64(key128, _mm_setzero_si128()), _mm_setzero_si128()));
        }

        void schwaemm256_128_avx2::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            alignas(32) uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x4000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);

            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x6000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x5000000, 0, 0, 0, 0, 0)); });

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x7000000, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);

            __m128i h = _mm_blend_epi32(_mm_shuffle_epi32(_mm256_extracti128_si256(HHy, 1), 0b01010000), _mm_shuffle_epi32(_mm256_extracti128_si256(HHx, 1), 0b01010000), 0b0101);
            if (tagsize_in_bytes() == tagsize_in_bytes_default())
                _mm_storeu_si128((__m128i*) out, h);
            else
            {
                _mm_storeu_si128((__m128i*) buf, h);
                memcpy(out, buf, tagsize_in_bytes());
            }

        }

        bool schwaemm256_128_avx2::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;
            alignas(32) uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 32; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x4000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 32 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x6000000, 0, 0, 0, 0, 0));
                _mm256_store_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010));

                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;
                absorb_decrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x5000000, 0, 0, 0, 0, 0)); });

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x7000000, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);

            __m128i h = _mm_blend_epi32(_mm_shuffle_epi32(_mm256_extracti128_si256(HHy, 1), 0b01010000), _mm_shuffle_epi32(_mm256_extracti128_si256(HHx, 1), 0b01010000), 0b0101);
            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                __m128i res = _mm_xor_si128(h, _mm_loadu_si128((__m128i*)(in + inlen - 16)));
                int result = _mm_testz_si128(res, res) - 1;
                return !result;
            }
            else
            {
                _mm_store_si128((__m128i*) buf, h);
                return tag_matches(buf, in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            }
        }

        schwaemm192_192_avx2::schwaemm192_192_avx2()
            : HHx(_mm256_setzero_si256())
            , HHy(_mm256_setzero_si256())
            , Hc(_mm256_loadu_si256((const __m256i*) C))
            , r16_128(_mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , r16_256(_mm256_set_epi8(29, 28, 31, 30, 25, 24, 27, 26, 21, 20, 23, 22, 17, 16, 19, 18, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
            , mask1(_mm256_setr_epi32(7, 7, 7, 0, 1, 2, 7, 7))
            , mask2(_mm256_set_epi32(7, 6, 2, 1, 0, 3, 5, 4))
            , mask3(_mm256_set_epi32(3, 3, 2, 2, 1, 1, 0, 0))
            , mask4(_mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0))
            , mask5(_mm256_set_epi32(6, 6, 5, 5, 4, 4, 3, 3))
            , mask6(_mm256_set_epi32(7, 7, 7, 7, 6, 5, 4, 3))
        {
        }

        inline void schwaemm192_192_avx2::sparkle_step_common(int i, __m256i& Hx, __m256i& Hy)
        {
            Hy = _mm256_xor_si256(Hy, _mm256_set_epi32(0, 0, 0, 0, 0, 0, i, C[i % 8]));
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 31), _mm256_slli_epi32(Hy, 32 - 31)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 24), _mm256_slli_epi32(Hx, 32 - 24)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 17), _mm256_slli_epi32(Hy, 32 - 17)));
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 17), _mm256_slli_epi32(Hx, 32 - 17)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, Hy);
            Hy = _mm256_xor_si256(Hy, _mm256_or_si256(_mm256_srli_epi32(Hx, 31), _mm256_slli_epi32(Hx, 32 - 31)));
            Hx = _mm256_xor_si256(Hx, Hc);
            Hx = _mm256_add_epi32(Hx, _mm256_or_si256(_mm256_srli_epi32(Hy, 24), _mm256_slli_epi32(Hy, 32 - 24)));
            Hy = _mm256_xor_si256(Hy, _mm256_shuffle_epi8(Hx, r16_256));
            Hx = _mm256_xor_si256(Hx, Hc);
        }

        inline void schwaemm192_192_avx2::sparkle_step_384(int i, __m256i& Hx, __m256i& Hy)
        {
            sparkle_step_common(i, Hx, Hy);
            Hx = _mm256_blend_epi32(_mm256_setzero_si256(), Hx, 0b00111111);
            Hy = _mm256_blend_epi32(_mm256_setzero_si256(), Hy, 0b00111111);
            __m128i xa = hxor3_epi32_avx(_mm256_castsi256_si128(Hx));
            __m128i ya = hxor3_epi32_avx(_mm256_castsi256_si128(Hy));
            xa = _mm_shuffle_epi8(_mm_xor_si128(xa, _mm_slli_epi32(xa, 16)), r16_128);
            ya = _mm_shuffle_epi8(_mm_xor_si128(ya, _mm_slli_epi32(ya, 16)), r16_128);
            Hx = _mm256_blend_epi32(Hx, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hx, mask1), Hx), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(ya), mask1)), 0b00111000);
            Hy = _mm256_blend_epi32(Hy, _mm256_xor_si256(_mm256_xor_si256(_mm256_permutevar8x32_epi32(Hy, mask1), Hy), _mm256_permutevar8x32_epi32(_mm256_broadcastsi128_si256(xa), mask1)), 0b00111000);
            Hx = _mm256_permutevar8x32_epi32(Hx, mask2);
            Hy = _mm256_permutevar8x32_epi32(Hy, mask2);
        }


        inline void schwaemm192_192_avx2::sparkle384_big()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_384(0, Hx, Hy);
            sparkle_step_384(1, Hx, Hy);
            sparkle_step_384(2, Hx, Hy);
            sparkle_step_384(3, Hx, Hy);
            sparkle_step_384(4, Hx, Hy);
            sparkle_step_384(5, Hx, Hy);
            sparkle_step_384(6, Hx, Hy);
            sparkle_step_384(7, Hx, Hy);
            sparkle_step_384(8, Hx, Hy);
            sparkle_step_384(9, Hx, Hy);
            sparkle_step_384(10, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm192_192_avx2::sparkle384_little()
        {
            __m256i Hx = HHx;
            __m256i Hy = HHy;

            sparkle_step_384(0, Hx, Hy);
            sparkle_step_384(1, Hx, Hy);
            sparkle_step_384(2, Hx, Hy);
            sparkle_step_384(3, Hx, Hy);
            sparkle_step_384(4, Hx, Hy);
            sparkle_step_384(5, Hx, Hy);
            sparkle_step_384(6, Hx, Hy);

            HHx = Hx;
            HHy = Hy;
        }

        inline void schwaemm192_192_avx2::absorb_encrypt(const unsigned char* in, unsigned char* out)
        {
            alignas(32) unsigned char buf[64];
            memcpy(buf, in, 24);
            memset(buf + 24, 0, 8);

            __m256i in256 = _mm256_load_si256((const __m256i*) buf);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            if (out)
            {
                _mm256_store_si256((__m256i*) buf, _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010)));
                memcpy(out, buf, 24);
            }

            __m128i xlow = _mm256_castsi256_si128(HHx);
            __m128i ylow = _mm256_castsi256_si128(HHy);

            __m128i xt = _mm_xor_si128(_mm_shuffle_epi32(ylow, 0b11001001), _mm_blend_epi32(_mm_shuffle_epi32(xlow, 0b11100011), _mm_setzero_si128(), 0b1010));
            __m128i yt = _mm_xor_si128(_mm_shuffle_epi32(xlow, 0b11010010), _mm_shuffle_epi32(ylow, 0b00100111));

            xt = _mm_xor_si128(xt, _mm_shuffle_epi32(_mm256_extracti128_si256(HHx, 1), 0b11010010));
            yt = _mm_xor_si128(yt, _mm_shuffle_epi32(_mm256_extracti128_si256(HHy, 1), 0b11010010));

            xt = _mm_blend_epi32(_mm_xor_si128(xt, _mm256_castsi256_si128(inr)), xlow, 0b1000);
            yt = _mm_blend_epi32(_mm_xor_si128(yt, _mm256_extracti128_si256(inr, 1)), ylow, 0b1000);

            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), xt);
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), yt);
        }

        inline void schwaemm192_192_avx2::absorb_decrypt(const uint8_t* in, uint8_t* out)
        {
            alignas(32) char buf[64];
            memcpy(buf, in, 24);
            memset(buf + 24, 0, 8);

            __m256i in256 = _mm256_load_si256((const __m256i*) buf);
            __m256i inr = _mm256_permutevar8x32_epi32(in256, mask4);

            _mm256_store_si256((__m256i*) buf, _mm256_xor_si256(in256, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010)));
            memcpy(out, buf, 24);

            __m128i xlow = _mm256_castsi256_si128(HHx);
            __m128i ylow = _mm256_castsi256_si128(HHy);

            __m128i xt = _mm_xor_si128(_mm_shuffle_epi32(ylow, 0b11001001), _mm_blend_epi32(xlow, _mm_setzero_si128(), 0b1100));
            __m128i yt = _mm_xor_si128(_mm_shuffle_epi32(xlow, 0b11010010), _mm_blend_epi32(ylow, _mm_setzero_si128(), 0b1110));

            xt = _mm_xor_si128(xt, _mm256_castsi256_si128(_mm256_permutevar8x32_epi32(HHx, mask6)));
            yt = _mm_xor_si128(yt, _mm256_castsi256_si128(_mm256_permutevar8x32_epi32(HHy, mask6)));

            xt = _mm_blend_epi32(_mm_xor_si128(xt, _mm256_castsi256_si128(inr)), xlow, 0b1000);
            yt = _mm_blend_epi32(_mm_xor_si128(yt, _mm256_extracti128_si256(inr, 1)), ylow, 0b1000);

            HHx = _mm256_set_m128i(_mm256_extracti128_si256(HHx, 1), xt);
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(HHy, 1), yt);
        }

        inline void schwaemm192_192_avx2::set_key_nonce_to_state(const unsigned char* key, const unsigned char* nonce)
        {
            alignas(32) char buf[64];
            memcpy(buf, nonce, 24);
            memcpy(buf + 24, key, 24);
            memset(buf + 48, 0, 16);

            __m256i noncet = _mm256_permutevar8x32_epi32(_mm256_load_si256((const __m256i*) buf), mask4);
            __m256i keyt = _mm256_permutevar8x32_epi32(_mm256_load_si256((const __m256i*) & buf[32]), mask4);
            HHx = _mm256_set_m128i(_mm256_castsi256_si128(keyt), _mm256_castsi256_si128(noncet));
            HHy = _mm256_set_m128i(_mm256_extracti128_si256(keyt, 1), _mm256_extracti128_si256(noncet, 1));
        }

        inline void schwaemm192_192_avx2::xor_key_to_state(const unsigned char* key)
        {
            alignas(32) char buf[64];
            memset(buf, 0, 24);
            memcpy(buf + 24, key, 24);
            memset(buf + 48, 0, 16);

            __m256i noncet = _mm256_permutevar8x32_epi32(_mm256_load_si256((const __m256i*) buf), mask4);
            __m256i keyt = _mm256_permutevar8x32_epi32(_mm256_load_si256((const __m256i*) & buf[32]), mask4);
            HHx = _mm256_xor_si256(HHx, _mm256_set_m128i(_mm256_castsi256_si128(keyt), _mm256_castsi256_si128(noncet)));
            HHy = _mm256_xor_si256(HHy, _mm256_set_m128i(_mm256_extracti128_si256(keyt, 1), _mm256_extracti128_si256(noncet, 1)));
        }

        void schwaemm192_192_avx2::encrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            alignas(32) uint8_t buf[32];

            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto encrypt_pt = [&](const unsigned char* in) { absorb_encrypt(in, out); out += 24; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x8000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto encrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0xA000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x9000000, 0, 0, 0, 0, 0)); });

            if (inlen)
                transform_blocks(in, inlen, encrypt_pt, encrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0xB000000, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);
            _mm256_store_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010));
            memcpy(out, buf, tagsize_in_bytes());
        }

        bool schwaemm192_192_avx2::decrypt(const unsigned char* key, const unsigned char* in, size_t inlen, const unsigned char* ad, size_t adlen, const unsigned char* iv, unsigned char* out)
        {
            if (inlen < tagsize_in_bytes())
                return false;
            alignas(32) uint8_t buf[32];
            auto absorb_ad = [this](const unsigned char* in) { absorb_encrypt(in, nullptr); };
            auto decrypt_ct = [&](const unsigned char* in) { absorb_decrypt(in, out); out += 24; };
            auto absorb_incomplete_ad = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x8000000, 0, 0, 0, 0, 0));
                memcpy(buf, in, static_cast<size_t>(length));
                memset(&buf[length], 0, 24 - static_cast<size_t>(length));
                buf[length] = 0x80;
                absorb_encrypt(buf, nullptr);
            };
            auto decrypt_incomplete_block = [&](const unsigned char* in, unsigned long long length)
            {
                HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0xA000000, 0, 0, 0, 0, 0));
                _mm256_store_si256((__m256i*) buf, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask3), _mm256_permutevar8x32_epi32(HHy, mask3), 0b10101010));

                memcpy(buf, in, static_cast<size_t>(length));
                buf[length] ^= 0x80;
                absorb_decrypt(buf, buf);
                memcpy(out, buf, static_cast<size_t>(length));
                out += length;
            };

            set_key_nonce_to_state(key, iv);
            sparkle384_big();

            if (adlen)
                transform_blocks(ad, adlen, absorb_ad, absorb_incomplete_ad,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0x9000000, 0, 0, 0, 0, 0)); });

            if (inlen - tagsize_in_bytes())
                transform_blocks(in, inlen - tagsize_in_bytes(), decrypt_ct, decrypt_incomplete_block,
                    [this]() { HHy = _mm256_xor_si256(HHy, _mm256_set_epi32(0, 0, 0xB000000, 0, 0, 0, 0, 0)); });

            xor_key_to_state(key);

            memcpy(buf, in + inlen - tagsize_in_bytes(), tagsize_in_bytes());
            memset(buf + tagsize_in_bytes(), 0, 32 - tagsize_in_bytes());
            if (tagsize_in_bytes() == tagsize_in_bytes_default())
            {
                __m256i res = _mm256_xor_si256(_mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010), _mm256_load_si256((__m256i*) buf));
                int result = _mm256_testz_si256(res, res) - 1;
                return !result;
            }
            alignas(32) uint8_t buf2[32];
            _mm256_store_si256((__m256i*) buf2, _mm256_blend_epi32(_mm256_permutevar8x32_epi32(HHx, mask5), _mm256_permutevar8x32_epi32(HHy, mask5), 0b10101010));
            return tag_matches(buf, buf2, tagsize_in_bytes());
        }

    }
}

