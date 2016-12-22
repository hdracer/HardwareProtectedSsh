SRC_DIR=./
CPPRESTINC_DIR=../../casablanca/Release/include
TPMINC_DIR=../TSS.MSR.CPP/Src
DEST_DIR=../linux
LIBNAME_BASE=libattestation

CC= g++
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -c -fPIC -Wall -Wno-unused-value -Wno-extra -Werror -Wno-unused-parameter -g -std=c++11 -I$(SRC_DIR) -I$(CPPRESTINC_DIR) -I$(TPMINC_DIR)
LIBNAME=$(LIBNAME_BASE)-x64.so
LIBPATH=$(DEST_DIR)/$(LIBNAME_BASE)-x64.so

SRCS = AttestationLib.cpp Helpers.cpp

OBJS = AttestationLib.o Helpers.o


all: LibCpp 

.cpp.o:
	$(CC) $(CFLAGS) $<

deps: Makefile.dep

Makefile.dep: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./Makefile.dep

-include Makefile.dep

LibCpp: deps $(OBJS)
	rm -rf $(DEST_DIR)/libattestation.a
	ar -cq $(DEST_DIR)/libattestation.a $(OBJS)
	rm -rf $(LIBPATH)

clean:
	-rm -f *.o
	-rm -f *$(DEST_DIR)/libattestation.a

distclean: clean
	-rm -f $(LIBPATH)
