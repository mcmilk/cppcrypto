ifeq ($(OS),Windows_NT)
  UNAME ?= Windows
else
  UNAME := $(shell uname -s)
endif

ifeq ($(UNAME),Darwin)
# OS X
PREFIX       ?= /usr/local
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := macho32
OBJ64FORMAT  := macho64
LDFLAGS=-lcppcrypto -lc++
CC=clang
CXX=clang++
endif

ifeq ($(UNAME),Linux)
# Linux
PREFIX       ?= /usr
ifeq ($(shell getconf LONG_BIT), 64)
LIBDIR       ?= $(PREFIX)/lib64
else
LIBDIR       ?= $(PREFIX)/lib
endif
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
LDFLAGS=-lcppcrypto -lstdc++ -lpthread
CC=gcc
CXX=g++
endif

ifeq ($(UNAME),FreeBSD)
# OS X
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
LDFLAGS=-lcppcrypto -lc++ -lpthread
CC=clang
CXX=clang++
endif

ifeq ($(UNAME),SunOS)
# Solaris
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
LDFLAGS=-L/usr/lib -lcppcrypto -std=c++11 -R '$$ORIGIN/../lib:/lib:/usr/lib' -fopenmp -O5
CC=CC
CXX=CC
MAKE_DIR = ginstall -d
INSTALL_DATA = ginstall
endif

ifeq ($(UNAME),Windows)
define \n


endef
$(error Windows build is supported only via Visual C++ project files,$(\n)or run 'make UNAME=Cygwin' to build for Cygwin)
endif

ifeq ($(UNAME),Cygwin)
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := win32
OBJ64FORMAT  := win64
LDFLAGS=-lstdc++ -Wl,--stack,16777216
LDEXTRALIBS=-lcppcrypto -lssp
CC=g++
CXX=g++
endif

ifndef OBJ64FORMAT
$(error Unsupported platform, please edit the makefile)
endif

BINDIR       ?= $(PREFIX)/bin
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

CXXFLAGS=-O2 -Wall -g -fstack-protector -fpermissive -std=gnu++11 -DNDEBUG -msse2

ifeq ($(shell getconf LONG_BIT), 64)
PLATFORM64BIT=1
else
PLATFORM64BIT=0
endif

ifeq ($(UNAME),SunOS)
CFLAGS=-O5 -xipo=2 -g -DNDEBUG -xarch=sse2 
CXXFLAGS=-O5 -xipo=2 -g -std=c++11 -DNDEBUG -xarch=sse2
ifeq ($(shell isainfo -v 2>&1 | grep -q "64-bit" && echo 64bit || echo 32bit), 64bit)
PLATFORM64BIT=1
CFLAGS += -m64
CXXFLAGS += -m64
LDFLAGS += -m64
endif
endif

ifeq ($(PLATFORM64BIT), 1)
   CFLAGS += -fPIC -D_M_X64
   CXXFLAGS += -fPIC -D_M_X64
else
endif


OBJS= perftimer.o digest.o

all: digest

digest: $(OBJS) 
	$(CC) $(LDFLAGS) -o digest $(OBJS) $(LDEXTRALIBS)

clean:
	rm -f *.o digest

install: digest
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(BINDIR)
	$(INSTALL_DATA) -pm 0755 digest $(DESTDIR)$(BINDIR)



