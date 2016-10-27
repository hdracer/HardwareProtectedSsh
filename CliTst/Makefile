CC = g++
DEBUG = -g
CFLAGS = -Wall -c $(DEBUG) -fPIC -D _TPMCPPLIB -std=c++11 -I../TSS.MSR.CPP/Src
CFLAGSTST = -Wall $(DEBUG) -std=c++11 -I../TSS.MSR.CPP/Src
LFLAGS = -Wall $(DEBUG)
VPATH = ../TSS.MSR.CPP/Src
SRCS = AuthSessions.cpp CryptoServices.cpp Helpers.cpp MarshallIn.cpp MarshallOut.cpp Policy.cpp stdafx.cpp TextSerializer.cpp Tpm2.cpp TpmCpp.cpp TpmCustomDefs.cpp TpmDevice.cpp TpmStructureBase.cpp TpmTypes.cpp TpmTypes_skel.cpp dllmain.cpp
OBJS = AuthSessions.o CryptoServices.o Helpers.o MarshallIn.o MarshallOut.o Policy.o stdafx.o TextSerializer.o Tpm2.o TpmCpp.o TpmCustomDefs.o TpmDevice.o TpmStructureBase.o TpmTypes.o TpmTypes_skel.o dllmain.o
OBJSTST = TpmCpp.a

all: TpmCpp CliTst

.cpp.o:
	$(CC) $(CFLAGS) $<

deps: Makefile.dep

Makefile.dep: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./Makefile.dep

-include Makefile.dep

TpmCpp: deps $(OBJS)
	rm -rf TpmCpp.a
	ar -cq TpmCpp.a $(OBJS)
	rm -rf TpmCpp.so
	g++ -shared -o TpmCpp.so $(OBJS)

CliTst: CliTst.cpp stdafx.cpp TpmCpp.a 
	$(CC) $(CFLAGSTST) -o CliTst CliTst.cpp stdafx.cpp $(OBJSTST) -L/usr/lib -L/usr/local/lib -lssl -lcrypto -lboost_system -lcpprest

clean:
	rm -rf CliTst
	rm -rf TpmCpp.a
	rm -rf TpmCpp.so
	rm -rf *.o
