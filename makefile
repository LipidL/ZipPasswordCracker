CFLAGS += -O2 -lm -std=gnu11 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable
CUDAFLAGS += -O2 -lm -std=c++20 -lineinfo
LDFLAGS += -L. -l pwd_validate
CCOMPILER = gcc
CUDACOMPILER = nvcc


all: encrypt.c zip.h encrypt.cu pwd_validate/src/*
	make cpu
	make gpu

cpu: encrypt.c zip.h
	$(CCOMPILER) -o cracker_cpu encrypt.c $(CFLAGS)

gpu: encrypt.cu *.h pwd_validate/src/*
# build the pwd_validate library
	cd pwd_validate && cargo build --release
# link the library to the current directory
	rm -f libpwd_validate.so
	ln -s pwd_validate/target/release/libpwd_validate.so .
# compile the CUDA code
	$(CUDACOMPILER) -o encrypt_cu encrypt.cu $(CUDAFLAGS) $(LDFLAGS)
# compile the pipeline code
	$(CCOMPILER) -o cracker_cuda pipelined_cuda.c $(CFLAGS) $(LDFLAGS)