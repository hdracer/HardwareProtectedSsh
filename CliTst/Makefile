CC = g++
DEBUG = -g
CFLAGS = -Wall -c $(DEBUG) -fPIC -D _TPMCPPLIB -std=c++11 -I../TSS.MSR.CPP/Src -I../libp11platformattestation
CFLAGSTST = -Wall $(DEBUG) -std=c++11 -I../TSS.MSR.CPP/Src -I../libp11platformattestation
LFLAGS = -Wall $(DEBUG)
DESTDIR= ../linux

all: CliTst

.cpp.o:
	$(CC) $(CFLAGS) $<

deps: Makefile.dep

Makefile.dep: $(SRCS)
	$(CC) $(CFLAGS) -MM $^ > ./Makefile.dep

-include Makefile.dep


CliTst: CliTst.cpp stdafx.cpp 
	$(CC) $(CFLAGSTST) -o CliTst CliTst.cpp stdafx.cpp -L/usr/lib -L/usr/local/lib -lssl -lcrypto -lboost_system -lcpprest -ldl

clean:
	rm -rf CliTst
	rm -rf *.o
