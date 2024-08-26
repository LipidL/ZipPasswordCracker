CFLAGS += -O0 -lm -std=gnu11 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable


all: encrypt.c zip.h
	gcc -o encrypt encrypt.c $(CFLAGS)

test: encrypt test.zip
	./encrypt test.zip 6