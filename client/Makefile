CC		= g++
CFLAGS	= -std=c++11 -lcrypto -lz -lpthread

TARGETS	= client.out

all: $(TARGETS)

client.out: pg3lib.h client.cpp
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm $(TARGETS)
