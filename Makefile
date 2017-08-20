CFLAGS=-Wall -Werror -Wno-extended-offsetof -pedantic -std=c99
LDLIBS=-ludis86

default: db

.PHONY: clean
clean:
	rm -f db
