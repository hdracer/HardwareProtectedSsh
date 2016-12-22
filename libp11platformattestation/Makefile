TPM_DIR=../TSS.MSR.CPP/Src
ATTESTATION_DIR=../AttestationLib
CPPRESTINC_DIR=../../casablanca/Release/include
SRC_DIR=./
DEST_DIR=../linux

CC= g++
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -Wall -Wno-extra -Werror -Wno-unused-parameter -g -std=c++11 -I$(SRC_DIR) -I$(CPPRESTINC_DIR) -I$(TPM_DIR) -I$(ATTESTATION_DIR)
LIBBASENAME=libp11platformattestation-x64.so
LIBNAME=$(DEST_DIR)/$(LIBBASENAME)

all: libp11platformattestation.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) libp11platformattestation.o -Wl,--whole-archive -L$(DEST_DIR) -lattestation -ltpmcpp -Wl,--no-whole-archive 

libp11platformattestation.o: $(SRC_DIR)/libp11platformattestation.cpp $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/libp11platformattestation.cpp

install:
	cp $(LIBNAME) /usr/local/lib
	chmod 0755 /usr/local/lib/$(LIBBASENAME)

clean:
	-rm -f *.o

distclean: clean
	-rm -f $(LIBNAME)
