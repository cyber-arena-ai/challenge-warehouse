CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -O3 -fno-PIC -fstack-protector-all -no-pie -s

.PHONY: all

all: cartography

cartography: cartography.c mars.h
	gcc ${CFLAGS} -o cartography cartography.c
