TPM_DIR=../TSS.MSR.CPP/Src
ATTESTATION_DIR=../AttestationLib
SRC_DIR=./
DEST_DIR=../linux

CC= gcc
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -Wall -Wno-extra -Werror -Wno-unused-parameter -g -std=c++11 -I$(SRC_DIR) -I$(TPM_DIR) -I$(ATTESTATION_DIR)
LIBNAME=$(DEST_DIR)/libp11platformattestation-x64.so

all: libp11platformattestation.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) libp11platformattestation.o

libp11platformattestation.o: $(SRC_DIR)/libp11platformattestation.cpp $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/libp11platformattestation.cpp

install:
	cp $(LIBNAME) /usr/local/lib
	chmod 0755 /usr/local/lib/$(LIBNAME)

clean:
	-rm -f *.o

distclean: clean
	-rm -f $(LIBNAME)
