CFLAGS += -O2 -lm -std=gnu11 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable
CPPFLAGS += -O2 -lm -std=c++20 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable
CUDAFLAGS += -Xptxas -O2 -lm -std=c++20 -lineinfo
LDFLAGS += -L. -l pwd_validate
CCOMPILER = gcc
CPPCOMPILER = g++
CUDACOMPILER = nvcc


all: encrypt.c *.h encrypt.cu pipelined_cuda.cpp pwd_validate/src/*
	make cpu
	make gpu

cpu: encrypt.c zip.h sha1.h
	$(CCOMPILER) -o cracker_cpu encrypt.c $(CFLAGS)

gpu: pipelined_cuda.cpp encrypt.cu sha1_cu.h rust_wrapper.h pwd_validate/src/* pwd_validate/Cargo.toml
# build the pwd_validate library
	cd pwd_validate && cargo build --release
# link the library to the current directory
	rm -f libpwd_validate.so
	ln -s pwd_validate/target/release/libpwd_validate.so .
# compile the CUDA code
	$(CUDACOMPILER) -o encrypt_cu encrypt.cu $(CUDAFLAGS) $(LDFLAGS)
# compile the pipeline code
	$(CPPCOMPILER) -o cracker_cuda pipelined_cuda.cpp $(CPPFLAGS) $(LDFLAGS)

clean:
	rm -f cracker_cpu cracker_cuda encrypt_cu libpwd_validate.so
	cd pwd_validate && cargo clean