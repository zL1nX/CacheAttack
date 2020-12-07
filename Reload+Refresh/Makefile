LIB_PATH = $(shell pwd)
CC=gcc
CFLAGS=-Werror

all: libT.so example_code sender sender_sync example_code_sync

example_code_sync: LDLIBS= -lm -L$(LIB_PATH) -lT
example_code_sync: common.o cache_utils.o example_code_sync.o

cache_utils.o: common.o

libT.so: T.o
	gcc -shared -o $(LIB_PATH)/$@ $^

T.o: T.c
	gcc -c -Wall -Werror -fpic $^

common.o: LDLIBS= -lm

sender_sync.o: sender_sync.c
	gcc -c -o $@ $^

sender_sync: sender_sync.o libT.so
	gcc -o $@ sender_sync.o -L$(LIB_PATH) -lT

clean:
	$(RM) *.o *~ *.so
	$(RM) 
