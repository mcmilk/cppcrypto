
# Git mirror of cppcrypto

cppcrypto provides optimized implementations of cryptographic primitives.

Includes sample command-line tools:
- 'digest' - for calculating and verifying file checksum(s) using any of the supported hash algorithms (similar to md5sum or RHash).
- 'cryptor' - for file encryption using Serpent-256 algorithm in AEAD mode.

Check out the [cppcrypto web site](https://sourceforge.net/projects/cppcrypto/) for programming documentation.

Features
- Simple self-explanatory programming interface.
- Hash functions: BLAKE, BLAKE2, Echo, Esch, Grøstl, JH, Kupyna, MD5, SHA-1, SHA-2, SHA-3, SHAKE, Skein, SM3, Streebog, Whirlpool.
- Block ciphers: Rijndael (AES), Anubis, Aria, Camellia, CAST-256, Kalyna, Kuznyechik, Mars, Serpent, Simon-128, SM4, Speck-128, Threefish, Twofish.
- Stream ciphers: HC-128, HC-256, Salsa20/20, Salsa20/12, XSalsa20/20, XSalsa20/12, ChaCha20, ChaCha12, XChaCha20, XChaCha12.
- Encryption modes: CBC, CTR.
- AEAD modes: Encrypt-then-MAC, GCM, OCB, ChaCha-Poly1305, Schwaemm.
- Streaming authenticated encryption with associated data (Streaming AEAD).
- MAC functions: HMAC, Poly1305.
- Key derivation functions: PBKDF2, scrypt, Argon2i/Argon2d/Argon2id, HKDF
- Tested compilers: Visual C++ 2017, Visual C++ 2019, Visual C++ 2022, gcc 12.2.1, clang 13.0.0, clang 15.0.7.
- Tested operating systems: Windows, Linux, FreeBSD, OS X, Solaris
- Includes portable implementations and optimized implementations (using SSE/AVX/etc) for modern CPUs.
- The fastest implementation is selected dynamically at runtime depending on CPU features.
- The only publicly-available implementation of AES-NI acceleration for all 25 Rijndael variants (not only for 3 AES variants).
- The only publicly-available performance-optimized implementation of Kupyna hash function (Ukrainian national standard DSTU 7564:2014).

# Author and reference

- Github page of [Keru Kuro](https://github.com/kerukuro)
- Sourceforge page of [Keru Kuro](https://sourceforge.net/u/kerukuro/profile/)
- Homepage of [cppcrypto](https://sourceforge.net/projects/cppcrypto/) @ Sourceforge

/TR 2024-01-13
