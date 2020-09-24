CC=gcc
CFLAGS=
LDFLAGS=

SRCS = main.c isg-attack-xmss.c isg-attack-xmss.h
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
