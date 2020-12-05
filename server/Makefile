CC		= g++
CFLAGS	= -std=c++11 -lcrypto -lz -lpthread

TARGETS	= server.out

all: $(TARGETS)

server.out: pg3lib.h server.cpp
	$(CC) $(CFLAGS) -o $@ $^


clean:
	rm $(TARGETS)
