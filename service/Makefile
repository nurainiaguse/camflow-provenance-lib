INCLUDES = -I../include
CCFLAGS = -g -O2 -fpic
CCC = gcc
LIB = ../src/provenancelib.a -lpthread -lz

.SUFFIXES: .c

all:
	$(CCC) $(INCLUDES) audit.c $(LIB) -o audit.o $(CCFLAGS)

debug:
	$(CCC) $(INCLUDES) audit.c $(LIB) -o audit.o $(CCFLAGS) -g

restart:
	systemctl restart camflow-provenance.service

install:
	cp --force ./audit.o /usr/bin/camflow-provenance
	mkdir -p /var/relay
	cp --force ./camflow-provenance.service /etc/systemd/system/camflow-provenance.service
	systemctl enable camflow-provenance.service

clean:
	rm -f audit.o
