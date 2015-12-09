ifeq ($(OS),Windows_NT)
  UNAME := Windows
else
  UNAME := $(shell uname -s)
endif

ifeq ($(UNAME),Darwin)
# OS X
PREFIX       ?= /usr/local
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := macho32
OBJ64FORMAT  := macho64
INLINE_AS := 1
LDFLAGS=-lc++
CC=clang
CXX=clang++
endif

ifeq ($(UNAME),Linux)
# Linux
PREFIX       ?= /usr
ifeq ($(shell getconf LONG_BIT), 64)
ifneq ($(wildcard $(PREFIX)/lib64/.),)
LIBDIR       ?= $(PREFIX)/lib64
else
LIBDIR       ?= $(PREFIX)/lib
endif
else
LIBDIR       ?= $(PREFIX)/lib
endif
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
INLINE_AS := 1
LDFLAGS=-Wl,-z,now -Wl,-z,relro -Wl,-soname,libcppcrypto.so.0
CC=gcc
CXX=g++
endif

ifeq ($(UNAME),FreeBSD)
# OS X
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
LDFLAGS=-lc++
CC=clang
CXX=clang++
endif

ifndef OBJ64FORMAT
$(error Unsupported platform $(UNAME), please edit the makefile)
endif

INCLUDEDIR   ?= $(PREFIX)/include/cppcrypto
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

# Other suppored options are clang and clang++

CFLAGS=-O2 -Wall -g -fstack-protector -DNDEBUG -msse2
CXXFLAGS=-O2 -Wall -g -fstack-protector -fpermissive -std=gnu++11 -DNDEBUG -msse2

cc-name = $(shell $(CC) -v 2>&1 | grep -q "clang version" && echo clang || echo gcc)
ifeq ($(cc-name),clang)
NOASFLAGS=-no-integrated-as
endif

OBJS= blake.o groestl.o cpuinfo.o sha256.o sha512.o skein256.o skein512.o skein1024.o whirlpool.o crypto_hash.o \
      blake256-sse2.o blake256-sse41.o blake512-sse2.o blake512-sse41.o groestl-impl-ssse3.o groestl-impl-aesni.o \
      kupyna.o rijndael.o cbc.o hmac.o rijndael-impl-aesni.o rijndael-impl-aesni-avx2.o pbkdf2.o anubis.o ctr.o \
      block_cipher.o twofish.o sha3.o sha3_impl_ssse3.o KeccakF-1600-opt64.o KeccakSponge.o jh.o sha1.o \
      jh-impl-sse.o streebog.o gost3411-2012-sse41.o sm3.o md5.o serpent.o cast6.o camellia.o kalyna.o \
	  aria.o

OBJS32 = skein512mmx.o sha512-nayuki.o whirlpool-nayuki.o sha1-nayuki.o serpent-waite.o
OBJS64 = b256avxs.o sha256_sse4.o sha512_sse4.o sha256_avx2_rorx2.o sha512_avx2_rorx.o \
         sha1_ssse3.o gost3411-2012-sse2.o

ifdef INLINE_AS
OBJS32 += sha256-cryptopp-x86-linux.o 
OBJS64 += sha256-cryptopp-x64-linux.o 
CXXFLAGS += -DINLINE_AS
endif

ifeq ($(shell getconf LONG_BIT), 64)
#ifeq ($(shell uname --hardware-platform), 86_64)
   CFLAGS += -fPIC -D_M_X64
   CXXFLAGS += -fPIC -D_M_X64
   OBJS += $(OBJS64)
else
   OBJS += $(OBJS32)
endif

all: libcppcrypto.so.0

libcppcrypto.so.0: $(OBJS) 
	$(CXX) $(LDFLAGS) -shared -o libcppcrypto.so.0  $(OBJS) -lm -lc $(LDEXTRALIBS)
	ar rcs libcppcrypto.a  $(OBJS)


clean:
	rm -f *.o 3rdparty/*.o libcppcrypto.so* libcppcrypto.a

install: libcppcrypto.so.0
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0755 libcppcrypto.so.0 $(DESTDIR)$(LIBDIR)
	cd $(DESTDIR)$(LIBDIR) && ln -s -f libcppcrypto.so.0 $(DESTDIR)$(LIBDIR)/libcppcrypto.so
	$(INSTALL_DATA) -pm 0644 *.h  $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0644 libcppcrypto.a $(DESTDIR)$(LIBDIR)

blake256-sse2.o: 3rdparty/blake256-sse2.c
	$(CC) -c $(CFLAGS) -msse2 3rdparty/blake256-sse2.c

blake256-sse41.o: 3rdparty/blake256-sse41.c
	$(CC) -c $(CFLAGS) -msse4.1 3rdparty/blake256-sse41.c

blake512-sse2.o: 3rdparty/blake512-sse2.c
	$(CC) -c $(CFLAGS) -msse2 3rdparty/blake512-sse2.c

blake512-sse41.o: 3rdparty/blake512-sse41.c
	$(CC) -c $(CFLAGS) -msse4.1 3rdparty/blake512-sse41.c

b256avxs.o: 3rdparty/b256avxs.asm
	yasm -f $(OBJ64FORMAT) -o b256avxs.o 3rdparty/b256avxs.asm

sha256_sse4.o: 3rdparty/sha256_sse4.asm
	yasm -f $(OBJ64FORMAT) -DLINUX -o sha256_sse4.o 3rdparty/sha256_sse4.asm

sha256_avx2_rorx2.o: 3rdparty/sha256_avx2_rorx2.asm
	yasm -f $(OBJ64FORMAT) -DLINUX -o sha256_avx2_rorx2.o 3rdparty/sha256_avx2_rorx2.asm

sha512_sse4.o: 3rdparty/sha512_sse4.asm
	yasm -f $(OBJ64FORMAT) -o sha512_sse4.o 3rdparty/sha512_sse4.asm

sha512_avx2_rorx.o: 3rdparty/sha512_avx2_rorx.asm
	yasm -f $(OBJ64FORMAT) -o sha512_avx2_rorx.o 3rdparty/sha512_avx2_rorx.asm

sha256-cryptopp-x64-linux.o: 3rdparty/sha256-cryptopp-x64-linux.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/sha256-cryptopp-x64-linux.cpp

groestl-impl-ssse3.o: 3rdparty/groestl-impl-ssse3.cpp
	$(CXX) -c $(CXXFLAGS) -mssse3 3rdparty/groestl-impl-ssse3.cpp

groestl-impl-aesni.o: 3rdparty/groestl-impl-aesni.cpp
	$(CXX) -c $(CXXFLAGS) -mssse3 -maes 3rdparty/groestl-impl-aesni.cpp

rijndael-impl-aesni.o: rijndael-impl-aesni.cpp
	$(CXX) -c $(CXXFLAGS) -msse4.1 -maes rijndael-impl-aesni.cpp

rijndael-impl-aesni-avx2.o: rijndael-impl-aesni-avx2.cpp
	$(CXX) -c $(CXXFLAGS) -mavx2 -maes rijndael-impl-aesni-avx2.cpp

skein512mmx.o: 3rdparty/skein512mmx.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/skein512mmx.cpp

sha512-nayuki.o: 3rdparty/sha512-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o sha512-nayuki.o 3rdparty/sha512-nayuki.asm

whirlpool-nayuki.o: 3rdparty/whirlpool-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o whirlpool-nayuki.o 3rdparty/whirlpool-nayuki.asm

sha256-cryptopp-x86-linux.o: 3rdparty/sha256-cryptopp-x86-linux.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 $(NOASFLAGS) 3rdparty/sha256-cryptopp-x86-linux.cpp

sha3_impl_ssse3.o: 3rdparty/sha3_impl_ssse3.cpp
	$(CXX) -c $(CXXFLAGS) -mssse3 3rdparty/sha3_impl_ssse3.cpp

KeccakSponge.o: 3rdparty/KeccakSponge.c
	$(CC) -c $(CFLAGS) -mssse3 3rdparty/KeccakSponge.c

KeccakF-1600-opt64.o: 3rdparty/KeccakF-1600-opt64.c
	$(CC) -c $(CFLAGS) -mssse3 3rdparty/KeccakF-1600-opt64.c

sha1-nayuki.o: 3rdparty/sha1-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o sha1-nayuki.o 3rdparty/sha1-nayuki.asm

sha1_ssse3.o: 3rdparty/sha1_ssse3.asm
	yasm -f $(OBJ64FORMAT) -o sha1_ssse3.o 3rdparty/sha1_ssse3.asm

jh-impl-sse.o: 3rdparty/jh-impl-sse.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/jh-impl-sse.cpp

gost3411-2012-sse2.o: 3rdparty/gost3411-2012-sse2.c
	$(CC) -c $(CFLAGS) -msse2 3rdparty/gost3411-2012-sse2.c

gost3411-2012-sse41.o: 3rdparty/gost3411-2012-sse41.c
	$(CC) -c $(CFLAGS) -msse4.1 3rdparty/gost3411-2012-sse41.c

serpent-waite.o: 3rdparty/serpent-waite.asm
	yasm -f $(OBJ32FORMAT) -o serpent-waite.o 3rdparty/serpent-waite.asm

