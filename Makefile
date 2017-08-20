CFLAGS=-Wall -Werror -pedantic -std=c99
LDLIBS=-ludis86

default: db

.PHONY: clean
clean:
	rm -f db
