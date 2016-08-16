INCLUDES = -I../include
CCFLAGS = -g -O2 -fpic
CCC = gcc
LIB = ../src/provenancelib.a -lpthread

.SUFFIXES: .c

all:
	$(CCC) $(INCLUDES) tool.c $(LIB) -o tool.o $(CCFLAGS)

debug:
	$(CCC) $(INCLUDES) tool.c $(LIB) -o tool.o $(CCFLAGS) -g

clean:
	rm -f tool.o

install:
	cp --force ./tool.o /usr/bin/camflow-prov
