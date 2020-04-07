CC=gcc
CFLAGS=-g -m64 -mavx2 -O3 -fomit-frame-pointer -funroll-all-loops -Wno-shift-count-overflow 
LDFLAGS=-L/usr/lib/ -lgdsl

SRCS = main.c 
OBJS = $(SRCS:.c=.o)
MAIN = main

.PHONY: depend clean

all: $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^
