CFLAGS += -O0 -lm -std=gnu11 -ggdb -Wall -Werror -Wno-unused-result -Wno-unused-value -Wno-unused-variable
CUDAFLAGS += -O0 -lm -std=c++20


all: encrypt.c zip.h encrypt.cu
	gcc -o encrypt encrypt.c $(CFLAGS)
	nvcc -o encrypt_cu encrypt.cu $(CUDAFLAGS)

cpu: encrypt.c zip.h
	gcc -o encrypt encrypt.c $(CFLAGS)

gpu: encrypt.cu zip.h
	nvcc -o encrypt_cu encrypt.cu $(CUDAFLAGS)