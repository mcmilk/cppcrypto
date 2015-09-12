PREFIX       ?= /usr/local
BINDIR       ?= $(PREFIX)/bin
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

CXX=g++
CXXFLAGS=-O2 -Wall -g -fstack-protector -fPIC -fpermissive -std=gnu++11 -D_M_X64 -lcppcrypto
LDFLAGS=-lcppcrypto -lstdc++

OBJS= perftimer.o digest.o

all: digest

digest: $(OBJS) 


clean:
	rm -f *.o digest

install: digest
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(BINDIR)
	$(INSTALL_DATA) -pm 0755 digest $(DESTDIR)$(BINDIR)



