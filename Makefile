CC=gcc
CFLAGS=-g -O -Wall -D_REENTRANT -DDEBUG
LIBPTHREAD= -lpthread

xotd: xotd.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBPTHREAD)

clean:
	rm -f xotd
