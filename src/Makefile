SRC = provenancelib.c provenanceProvJSON.c provenanceutils.c provenancefilter.c relay.c
OBJ = $(SRC:.c=.o)
OUT = provenance.a
INCLUDES = -I../threadpool -I../include -I../uthash/uthash/src
CCFLAGS = -g -O2 -fpic
CCC = gcc
LDFLAGS = -g

.SUFFIXES: .c

all: static

static: $(OUT)

.c.o:
	$(CCC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs provenance.a $(OBJ)
	ar -M <provenancelib.mri

clean:
	rm -f $(OBJ) $(OUT)
	rm -f *.a

install:
	cp --force ./provenancelib.a /usr/local/lib/provenancelib.a
