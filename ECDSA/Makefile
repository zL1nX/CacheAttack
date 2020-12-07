LIB_PATH = $(shell pwd)
CC=gcc
CFLAGS=-Werror

all: victim attacker 

attacker: LDLIBS= -lm -L../openssl-1.0.2h/ -lcrypto -ldl
attacker: cache_utils.o attacker.o


cache_utils.o: cache_utils.c

victim.o: victim.c
	gcc -c -o $@ $^

victim: cache_utils.o victim.o 
	gcc -o $@ $^ -L../openssl-1.0.2h/ -lcrypto
	

clean:
	$(RM) *.o *~ *.so
	$(RM) 
