TPM_DIR=../TSS.MSR.CPP/Src
ATTESTATION_DIR=../AttestationLib
CPPRESTINC_DIR=../../casablanca/Release/include
SRC_DIR=./
DEST_DIR=../linux

CC= g++
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -c -fPIC -Wall -Wno-extra -Werror -Wno-unused-parameter -g -std=c++11 -I$(SRC_DIR) -I$(CPPRESTINC_DIR) -I$(TPM_DIR) -I$(ATTESTATION_DIR)
LIBBASENAME=libp11platformattestation-x64.so
LIBNAME=$(DEST_DIR)/$(LIBBASENAME)
LIBDEST=/usr/lib/x86_64-linux-gnu/$(LIBBASENAME)

SRCS = libp11platformattestation.cpp p11helpers.cpp 
OBJS = libp11platformattestation.o p11helpers.o 

all: LibCpp 

.cpp.o:
	$(CC) $(CFLAGS) $<

deps: Makefile.dep

Makefile.dep: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./Makefile.dep

-include Makefile.dep

LibCpp: deps $(OBJS)

	$(CC) $(ARCH_FLAGS) -std=c++11 -shared -o $(LIBNAME) $(OBJS) -Wl,--whole-archive -L$(DEST_DIR) -lattestation -ltpmcpp -Wl,--no-whole-archive -lboost_system -lboost_filesystem -lcrypto -lssl -lcpprest


install:
	cp $(LIBNAME) $(LIBDEST)
	chmod 0755 $(LIBDEST)

clean:
	-rm -f *.o

distclean: clean
	-rm -f $(LIBNAME)
