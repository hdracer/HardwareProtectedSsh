ATTESTATION_DIR=../AttestationLib
SRC_DIR=./
DEST_DIR=../../linux
LIBNAME_BASE=libtpmcpp

CC= g++
ARCH_FLAGS= -m64
DEBUG = -Og -g
CFLAGS= $(ARCH_FLAGS) -c $(DEBUG) -fPIC -D _TPMCPPLIB -Wall -Wno-unused-value -Wno-extra -Werror -Wno-unused-parameter -std=c++11 -I$(SRC_DIR) 

LIBNAME=$(LIBNAME_BASE)-x64.so
LIBPATH=$(DEST_DIR)/$(LIBNAME_BASE).a

SRCS = AuthSessions.cpp CryptoServices.cpp Helpers.cpp MarshallIn.cpp MarshallOut.cpp Policy.cpp stdafx.cpp TextSerializer.cpp Tpm2.cpp TpmCpp.cpp TpmCustomDefs.cpp TpmDevice.cpp TpmStructureBase.cpp TpmTypes.cpp TpmTypes_skel.cpp dllmain.cpp

OBJS = AuthSessions.o CryptoServices.o Helpers.o MarshallIn.o MarshallOut.o Policy.o stdafx.o TextSerializer.o Tpm2.o TpmCpp.o TpmCustomDefs.o TpmDevice.o TpmStructureBase.o TpmTypes.o TpmTypes_skel.o dllmain.o


all: TpmCpp 

.cpp.o:
	$(CC) $(CFLAGS) $<

deps: Makefile.dep

Makefile.dep: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./Makefile.dep

-include Makefile.dep

TpmCpp: deps $(OBJS)
	rm -rf $(LIBPATH)
	ar -cq $(LIBPATH) $(OBJS)

clean:
	-rm -f *.o
	-rm -f $(LIBPATH)

distclean: clean
	-rm -f $(LIBPATH)
