PREFIX       ?= /usr/local
LIBDIR       ?= $(PREFIX)/lib
INCLUDEDIR   ?= $(PREFIX)/include/cppcrypto
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

CXX=g++
CFLAGS=-O2 -Wall -g -fstack-protector -DNDEBUG
CXXFLAGS=-O2 -Wall -g -fstack-protector -fpermissive -std=gnu++11 -DNDEBUG
LDFLAGS=-Wl,-z,now -Wl,-z,relro -Wl,-soname,libcppcrypto.so.0


OBJS= blake.o groestl.o cpuinfo.o sha256.o sha512.o skein256.o skein512.o skein1024.o whirlpool.o crypto_hash.o \
      blake256-sse2.o blake256-sse41.o blake512-sse2.o blake512-sse41.o groestl-impl-ssse3.o groestl-impl-aesni.o

OBJS32 = skein512mmx.o sha512-nayuki.o whirlpool-nayuki.o sha256-cryptopp-x86-linux.o
OBJS64 = b256avxs.o sha256_sse4.o sha512_sse4.o sha256_avx2_rorx2.o sha512_avx2_rorx.o sha256-cryptopp-x64-linux.o 


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
	$(CC) $(LDFLAGS) -shared -o libcppcrypto.so.0  $(OBJS) -lm -lc
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
	yasm -f elf64 -o b256avxs.o 3rdparty/b256avxs.asm

sha256_sse4.o: 3rdparty/sha256_sse4.asm
	yasm -f elf64 -DLINUX -o sha256_sse4.o 3rdparty/sha256_sse4.asm

sha256_avx2_rorx2.o: 3rdparty/sha256_avx2_rorx2.asm
	yasm -f elf64 -DLINUX -o sha256_avx2_rorx2.o 3rdparty/sha256_avx2_rorx2.asm

sha512_sse4.o: 3rdparty/sha512_sse4.asm
	yasm -f elf64 -o sha512_sse4.o 3rdparty/sha512_sse4.asm

sha512_avx2_rorx.o: 3rdparty/sha512_avx2_rorx.asm
	yasm -f elf64 -o sha512_avx2_rorx.o 3rdparty/sha512_avx2_rorx.asm

sha256-cryptopp-x64-linux.o: 3rdparty/sha256-cryptopp-x64-linux.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/sha256-cryptopp-x64-linux.cpp

groestl-impl-ssse3.o: 3rdparty/groestl-impl-ssse3.cpp
	$(CXX) -c $(CXXFLAGS) -mssse3 3rdparty/groestl-impl-ssse3.cpp

groestl-impl-aesni.o: 3rdparty/groestl-impl-aesni.cpp
	$(CXX) -c $(CXXFLAGS) -mssse3 -maes 3rdparty/groestl-impl-aesni.cpp

skein512mmx.o: 3rdparty/skein512mmx.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/skein512mmx.cpp

sha512-nayuki.o: 3rdparty/sha512-nayuki.asm
#	yasm -f elf32 -r raw -p gas -o sha512-nayuki.o 3rdparty/sha512-nayuki.asm
	as -o sha512-nayuki.o 3rdparty/sha512-nayuki.asm
#	$(CC) -c $(CFLAGS) -msse2 3rdparty/sha512-nayuki.asm

whirlpool-nayuki.o: 3rdparty/whirlpool-nayuki.asm
	as -o whirlpool-nayuki.o 3rdparty/whirlpool-nayuki.asm

sha256-cryptopp-x86-linux.o: 3rdparty/sha256-cryptopp-x86-linux.cpp
	$(CXX) -c $(CXXFLAGS) -msse2 3rdparty/sha256-cryptopp-x86-linux.cpp

