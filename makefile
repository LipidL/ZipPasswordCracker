CFLAGS += -O0 -lm -std=gnu11 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable
CUDAFLAGS += -O0 -lm -std=c++20 -lineinfo


all: encrypt.c zip.h encrypt.cu pwd_validate/*
# build the pwd_validate library
	cd pwd_validate && cargo build --release
# link the library to the current directory
	rm -f libpwd_validate.so
	ln -s pwd_validate/target/release/libpwd_validate.so .
	gcc -o encrypt encrypt.c $(CFLAGS)
	nvcc -o encrypt_cu encrypt.cu $(CUDAFLAGS) -L.  -l pwd_validate

cpu: encrypt.c zip.h
	gcc -o encrypt encrypt.c $(CFLAGS)

gpu: encrypt.cu zip.h
	nvcc -o encrypt_cu encrypt.cu $(CUDAFLAGS)