CC = cc
CFLAGS = -ggdb -Wall

default: all

all:
	${CC} ${CFLAGS} isn-get.c -lpcap -lnet -o isn-get

clean:
	rm -rf isn-get
