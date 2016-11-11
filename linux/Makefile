# Display exported symbols:
#  nm -D pkcs11-mock.so | grep ' T '

SRC_DIR=../libp11platformattestation

CC= gcc
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -g -I$(SRC_DIR)
LIBNAME=libp11platformattestation-x64.so

all: libp11platformattestation.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,libp11platformattestation.version \
	libp11platformattestation.o

libp11platformattestation.o: $(SRC_DIR)/libp11platformattestation.cpp $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/libp11platformattestation.cpp

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
