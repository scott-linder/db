CFLAGS=-Wall -Werror -pedantic
LDLIBS=-ludis86

default: db

.PHONY: clean
clean:
	rm -f db
