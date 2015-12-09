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
$(error Unsupported platform, please edit the makefile)
endif

BINDIR       ?= $(PREFIX)/bin
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

CXXFLAGS=-O2 -Wall -g -fstack-protector -fpermissive -std=gnu++11 -DNDEBUG -msse2
LDFLAGS=-lcppcrypto -lstdc++

ifeq ($(shell getconf LONG_BIT), 64)
   CFLAGS += -fPIC -D_M_X64
   CXXFLAGS += -fPIC -D_M_X64
else
endif


OBJS= perftimer.o digest.o

all: digest

digest: $(OBJS) 


clean:
	rm -f *.o digest

install: digest
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(BINDIR)
	$(INSTALL_DATA) -pm 0755 digest $(DESTDIR)$(BINDIR)



