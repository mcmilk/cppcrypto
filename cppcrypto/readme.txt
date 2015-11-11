cppcrypto is a small BSD-licensed C++ library providing some cryptographic primitives.
It has no external dependencies.

At the moment it supports the following primitives.

1) Hash functions: blake, groestl, sha-2 (incl. sha512/224 and sha512/256), sha-3, skein-256, skein-512, skein-1024,
whirlpool, kupyna.

To get the full list of supported hash algorithms, run 'digest' in hash function performance test mode:

  digest test <number_of_iterations> <filename>

2) Block ciphers: Anubis, Rijndael with block sizes 128, 192, 256 and key sizes 128, 160, 192, 224, 256
(all variants are accelerated using AES-NI instructions, if available), Twofish.

To get the full list of supported block ciphers, run 'digest' in block cipher performance test mode:

  digest bctest <number_of_iterations> <filename>

3) Encryption modes: CBC, CTR.
4) MAC functions: HMAC.

The library detects CPU type at runtime and uses optimized implementations where possible.

Supported compilers: Visual C++ 2013, Visual C++ 2015 on Windows; gcc 5.1.1 on Linux (not tested with older versions).
Supported architectures: x86_64 and x86.

Sample usage:

    #include "cppcrypto.h"

    // Calculate SHA-512/256 hash of a string
    string str = "The quick brown fox jumps over the lazy dog";
    uint8_t hash[32];
    
    sha512_256().hash_string(str, hash);


If you need to calculate hash of long message using chunks of data, use the init/update/final interface:

    sha512_256 hasher;
    uint8_t hash[32];
    
    hasher.init();
    hasher.update(chunk1, chunk1len);
    hasher.update(chunk2, chunk2len);
    ...
    hasher.final(hash);


Also included is a command-line utility 'digest.exe' which can be used to calculate hash sum of any file(s)
using any of the supported algorithms (similar to md5sum), for example, if you want to calculate
Skein-512/256 hash of a file, you can run:

   digest skein512/256 file.ext

Like md5sum, it can also verify checksums saved in a file, for example, if you want to verify saved
Groestl hashes, you can run:

   digest -c groestl256 checksums.grøstl


To build cppcrypto from the sources you need to have yasm installed.

If you are on Windows, note that the latest stable release of vsyasm (1.3.0) ships
vsyasm.props file which is not compatible with Visual Studio 2013 and 2015, so you
have to fix it manually or use the one included in the cppcrypto source arhive.

If you use the precompiled libraries on Windows then you don't need yasm.
Just link against cppcryptomd.lib or cppcryptomt.lib depending on your /MT or /MD settings. 

If you are on Linux, just run make and make install as usual.

For more information, see the web site: http://cppcrypto.sourceforge.net
