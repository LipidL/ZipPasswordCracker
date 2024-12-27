#include "zip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#include "sha1_cu.h"
#include "rust_wrapper.h"

#define BLOCK_SIZE 64
#define MAX_PWD_LENGTH 64
#define PWD_BUFFER_SIZE 1024

// a circular buffer
typedef struct circular_buffer {
    char buffer[MAX_PWD_LENGTH][PWD_BUFFER_SIZE];
    unsigned long long reader; // reader can be larger than PWD_BUFFER_SIZE, the actual reader position is reader % PWD_BUFFER_SIZE
    unsigned long long writer; // writer can be larger than PWD_BUFFER_SIZE, the actual writer position is writer % PWD_BUFFER_SIZE
} circular_buffer;

struct thread_data{
    u16 key_length;
    u8 *salt;
    u16 salt_length;
    u16 pwd_verification;
    u64 pwd_length; // maximum password length
    char *legal_chars;
    u64 legal_chars_length;
    u64 num_threads;
    // address of needed memory block in threads
    u8 *derived_key; // needed in is_valid_key()
    u8 *long_salt; // needed in PBKDF2()
    u8 *first_part_1; // needed in first call to HMAC_SHA1()
    u8 * first_part_2; // needed in second call to HMAC_SHA1()
    u8 *second_part; // needed in both calls to HMAC_SHA1()
    circular_buffer *pwd_buffer; // the buffer to store valid passwords
};

__device__ size_t device_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0' && len <= MAX_PWD_LENGTH) {
        len++;
    }
    return len;
}

__device__ size_t device_strcpy(char *dest, const char *src) {
    size_t i = 0;
    while (src[i] != '\0' && i < MAX_PWD_LENGTH) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    return i;
}

template <int DATA_LENGTH>
__device__ void HMAC_SHA1(
    unsigned char *key, uint64_t key_length,
    unsigned char *data,
    unsigned char hash[20]) 
{

    unsigned char i_key_pad[BLOCK_SIZE];
    unsigned char o_key_pad[BLOCK_SIZE];
    unsigned char temp_key[BLOCK_SIZE];

    if (key_length > BLOCK_SIZE) {
        sha1(key, key_length, temp_key);
        key = temp_key;
        key_length = 20;
    }

    memset(i_key_pad, 0, sizeof(i_key_pad));
    memset(o_key_pad, 0, sizeof(o_key_pad));

    memcpy(i_key_pad, key, key_length);
    memcpy(o_key_pad, key, key_length);

    for (int i = 0; i < BLOCK_SIZE; i++) {
        i_key_pad[i] ^= 0x36;
        o_key_pad[i] ^= 0x5c;
    }

    unsigned char first_hash[20];
    unsigned char first_part[BLOCK_SIZE + DATA_LENGTH];
    memcpy(first_part, i_key_pad, BLOCK_SIZE);
    memcpy(first_part + BLOCK_SIZE, data, DATA_LENGTH);
    sha1(first_part, BLOCK_SIZE + DATA_LENGTH, first_hash);

    unsigned char second_part[BLOCK_SIZE + 20];
    memcpy(second_part, o_key_pad, BLOCK_SIZE);
    memcpy(second_part + BLOCK_SIZE, first_hash, 20);
    sha1(second_part, BLOCK_SIZE + 20, hash);
}

__device__ void PBKDF2_HMAC_SHA1(unsigned char *password, uint64_t password_length,
                      unsigned char *salt, uint64_t salt_length,
                      uint64_t iteration_count, uint64_t derived_key_length,
                      u8 *long_salt,
                      unsigned char *derived_key) {
    
    u64 i, j, k, blocks;
    u8 hash[20], previous_hash[20], xor_hash[20];
    
    memset(long_salt, 0, salt_length + 4);
    memcpy(long_salt, salt, salt_length);
    blocks = (derived_key_length + 19) / 20;
    
    for (i = 0; i < blocks; i++) {
        long_salt[salt_length] = ((i + 1) >> 24) & 0xFF;
        long_salt[salt_length + 1] = ((i + 1) >> 16) & 0xFF;
        long_salt[salt_length + 2] = ((i + 1) >> 8) & 0xFF;
        long_salt[salt_length + 3] = (i + 1) & 0xFF;

        switch (salt_length) {
            case 8:
                HMAC_SHA1<8 + 4>(password, password_length, long_salt, previous_hash);
                break;
            case 12:
                HMAC_SHA1<12 + 4>(password, password_length, long_salt, previous_hash);
                break;
            case 16:
                HMAC_SHA1<16 + 4>(password, password_length, long_salt, previous_hash);
                break;
            default:
                assert(0); // should never happen
        }

        memcpy(xor_hash, previous_hash, 20);

        for (j = 1; j < iteration_count; j++) {
            HMAC_SHA1<20>(password, password_length, previous_hash, hash);
            memcpy(previous_hash, hash, 20);
            for (k = 0; k < 20; k++) {
                xor_hash[k] ^= hash[k];
            }
        }
        memcpy(derived_key + i * 20, xor_hash, (i == blocks - 1 && derived_key_length % 20) ? derived_key_length % 20 : 20);
    }
}

__device__ bool is_valid_key(u8 *key, u16 key_length, u8 *salt, u16 salt_length, u16 pwd_verification, u8 *long_salt, u8 *first_part_1, u8 *first_part_2, u8 *second_part, u8 *derived_key) {
    
    u64 derived_key_length = 2 * key_length + 2;
    PBKDF2_HMAC_SHA1(key, device_strlen((const char *)key), salt, salt_length, 1000, derived_key_length, long_salt, derived_key);
    if (derived_key[derived_key_length - 2] != (u8)((pwd_verification) & 0xFF) || derived_key[derived_key_length - 1] != (u8)((pwd_verification) >> 8)) {
        return false;
    }
    return true;
}

__device__ u64 add(int64_t test_pwd_num[MAX_PWD_LENGTH], u64 a, u64 legal_chars_length)
{
    // add test_pwd_num by a
    u64 carry = 0;
    int64_t add_result = test_pwd_num[0] + a;
    test_pwd_num[0] = add_result % legal_chars_length;
    carry = add_result / legal_chars_length;
    for(size_t i = 1; i < MAX_PWD_LENGTH; i++){
        if(carry == 0)
            break;
        add_result = test_pwd_num[i] + carry;
        test_pwd_num[i] = add_result % legal_chars_length;
        carry = add_result / legal_chars_length;
    }
    return carry;
}

__device__ void num_to_pwd(int64_t test_pwd_num[MAX_PWD_LENGTH], char *test_pwd, char *legal_chars)
{
    for(size_t i = 0; i < MAX_PWD_LENGTH; i++){
        test_pwd[i] = '\0';
        if(test_pwd_num[i] == -1){
            break;
        }
        test_pwd[i] = legal_chars[test_pwd_num[i]];

    }
    
}

__global__ void validate_key_thread(struct thread_data *data)
{
    // identify thread id
    u64 thread_id = blockIdx.x * blockDim.x + threadIdx.x; 
    assert(thread_id < data->num_threads); // make sure thread_id is valid
    int64_t test_pwd_num[MAX_PWD_LENGTH];
    char test_pwd[MAX_PWD_LENGTH + 1];
    memset(test_pwd_num, -1, MAX_PWD_LENGTH * sizeof(int64_t));
    memset(test_pwd, '\0', MAX_PWD_LENGTH + 1);
    // initialize thread pwd
    if(add(test_pwd_num, thread_id + 1, data->legal_chars_length) != 0){
        return;
    }
    double count = (pow((double)(data->legal_chars_length), (double)data->pwd_length + 1) - 1) / data->pwd_length / data->num_threads;
    for(size_t i = 0; i < count; i++){
        num_to_pwd(test_pwd_num, test_pwd, data->legal_chars);
        int str_len = device_strlen(test_pwd);
        if(str_len > data->pwd_length){
            return;
        }
        u8 *long_salt = data->long_salt + thread_id * (data->salt_length + 4);
        u8 *first_part_1 = data->first_part_1 + thread_id * (BLOCK_SIZE + data->salt_length + 4);
        u8 *first_part_2 = data->first_part_2 + thread_id * (BLOCK_SIZE + 20);
        u8 *second_part = data->second_part + thread_id * (BLOCK_SIZE + 20);
        u8 *derived_key = data->derived_key + thread_id * (2 * data->key_length + 2);
        if(is_valid_key((u8*)test_pwd, data->key_length, data->salt, data->salt_length, data->pwd_verification, long_salt, first_part_1, first_part_2, second_part, derived_key)){
            // store valid pwd to buffer
            unsigned long long writer = atomicAdd(&(data->pwd_buffer->writer), 1); // this function returns the value before increment
            writer = writer % PWD_BUFFER_SIZE;
            device_strcpy(data->pwd_buffer->buffer[writer], test_pwd);
        }
        if(add(test_pwd_num, data->num_threads, data->legal_chars_length) != 0){
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <file> <max_pwd_length>\n", argv[0]);
        return 1;
    }

    u16 max_pwd_length = atoi(argv[2]);
    
    struct local_file_header *header;
    struct aes_header *aes_header;
    
    // open the file
    printf("Opening file %s\n", argv[1]);
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    // get file size
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        return 1;
    }
    off_t size = st.st_size;
    void *file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    header = (struct local_file_header *)file;
    if (header->signature != 0x04034b50) {
        printf("Invalid signature\n");
        return 1;
    }
    else
        printf("Signature: 0x%08x\n", header->signature);
    if ((header->general_purpose_bit_flag & 0x1) != 0x1) {
        printf("File is not encrypted\n"); // encrypted files have the first bit set to 1
        return 1;
    }
    else    
        printf("File is encrypted\n");
    if (header->compression_method != 0x63) {
        printf("Invalid compression method\n"); // 0x63 is the AES encryption method (decimal 99)
        return 1;
    }
    uint64_t offset = sizeof(struct local_file_header) + header->file_name_length; // skip the header and the file name
    aes_header = (struct aes_header *)((char*)file + offset);   // sizeof(char) is always 1 according to C99 standard
                                                                // use this to walkaround the pointer arithmetic issue
    if (aes_header->signature != 0x9901) {
        printf("Invalid AES header signature\n");
        return 1;
    }
    if (aes_header->vendor_id[0] != 'A' || aes_header->vendor_id[1] != 'E') {
        printf("Invalid vendor ID\n");
        return 1;
    }
    if (aes_header->version_number != 0x0001 && aes_header->version_number != 0x0002){
        printf("Invalid AES encryption version\n");
        return 1;
    }
    u16 version = aes_header->version_number;
    if (version == 2 && header->crc32 ){
        printf("CRC32 should not present in AES-2 encrypted file\n");
        return 1;
    }
    // extract AES encryption strength
    // AES-128 = 1, AES-192 = 2, AES-256 = 3
    u8 salt_length;
    switch (aes_header->aes_encryption_strength){
    case 1:
        salt_length = 8;
        break;
    case 2:
        salt_length = 12;
        break;
    case 3:
        salt_length = 16;
        break;
    default:
        assert(0); // should never happen
    }
    u16 key_length = salt_length * 2;
    u8 *salt = (u8 *)((char*)file + offset + sizeof(struct aes_header));
    u16 *pwd_verification = (u16 *)(salt + salt_length);
    // print necessary information for debugging
    printf("salt_length is %d\n", salt_length);
    printf("key_length is %d\n", key_length);

    // find the number of GPU's multiprocessors
    int num_multiprocessors;
    cudaDeviceGetAttribute(&num_multiprocessors, cudaDevAttrMultiProcessorCount, 0);
    printf("num_multiprocessors: %d\n", num_multiprocessors);
    // calculate num_threads based on num_multiprocessors
    u64 num_threads = num_multiprocessors * 256; // 256 threads per block

    // copy salt and pwd_verification to device
    u8 *d_salt, *d_pwd_verification;
    cudaMalloc((void**)&d_salt, salt_length * sizeof(char));
    cudaMalloc((void**)&d_pwd_verification, 2 * sizeof(char));
    cudaMemcpy(d_salt, salt, salt_length * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_pwd_verification, pwd_verification, 2 * sizeof(char), cudaMemcpyHostToDevice);

    // initialize the circular buffer
    circular_buffer *pwd_buffer;
    // the circular buffer should be accessible by all threads in the device and host
    cudaMallocManaged(&pwd_buffer, sizeof(circular_buffer));
    // initialize the buffer
    for(size_t i = 0; i < MAX_PWD_LENGTH; i++){
        memset(pwd_buffer->buffer[i], '\0', PWD_BUFFER_SIZE);
    }
    pwd_buffer->reader = 0;
    pwd_buffer->writer = 0;

    // test pwd traversal

    // possible pwd: 0123456789
    u64 legal_chars_length = 10;
    char *legal_chars = (char*)malloc(10 * sizeof(char));
    for(size_t i = 0; i < 10; i++){
        legal_chars[i] = '0' + i;
    }

    // copy legal_chars to device
    char *d_legal_chars;
    cudaMalloc((void**)&d_legal_chars, 10 * sizeof(char));
    cudaMemcpy(d_legal_chars, legal_chars, 10 * sizeof(char), cudaMemcpyHostToDevice);

    // allocate necessary memory needed in each thread
    u8 *d_derived_key, *d_long_salt, *d_first_part_1, *d_first_part_2, *d_second_part;
    // the memory is needed in each thread, allocate one for each of them
    // each thread should use [d_derived_key+thread_id*(2*key_length+2), d_derived_key*(thread_id+1)*(2*key_length+2)] region for derived_key
    cudaMalloc((void**)&d_derived_key, (2 * key_length + 2) * num_threads);
    cudaMalloc((void**)&d_long_salt, (salt_length + 4) * num_threads);
    cudaMalloc((void**)&d_first_part_1, (BLOCK_SIZE + salt_length + 4) * num_threads);
    cudaMalloc((void**)&d_first_part_2, (BLOCK_SIZE + 20) * num_threads);
    cudaMalloc((void**)&d_second_part, (BLOCK_SIZE + 20) * num_threads);

    // construct threads
    struct thread_data data;

    data.key_length = key_length;
    data.legal_chars = d_legal_chars;
    data.legal_chars_length = legal_chars_length;
    data.num_threads = num_threads;
    data.pwd_length = max_pwd_length;
    data.pwd_verification = *pwd_verification;
    data.salt = d_salt;
    data.salt_length = salt_length;
    data.derived_key = d_derived_key;
    data.long_salt = d_long_salt;
    data.first_part_1 = d_first_part_1;
    data.first_part_2 = d_first_part_2;
    data.second_part = d_second_part;
    data.pwd_buffer = pwd_buffer;

    // copy data to device
    struct thread_data *d_data;
    cudaMalloc((void**)&d_data, sizeof(struct thread_data));
    cudaMemcpy(d_data, &data, sizeof(struct thread_data), cudaMemcpyHostToDevice);

    // configure thread and block size
    dim3 threads_per_block(256,1);
    dim3 num_blocks(num_multiprocessors, 1);
    printf("num_threads: %ld\n", num_threads);
    printf("threads_per_block: (%d, %d)\n", threads_per_block.x, threads_per_block.y);
    printf("num_blocks: (%d, %d)\n", num_blocks.x, num_blocks.y);
    assert(num_threads % threads_per_block.x == 0);
    assert(num_threads % threads_per_block.y == 0);

    // launch threads
    validate_key_thread<<<num_blocks, threads_per_block>>>(d_data);


    // wait until all threads finish
    cudaDeviceSynchronize();

    // print the result from the buffer
    while (1) {
        unsigned long long reader = pwd_buffer->reader % PWD_BUFFER_SIZE;
        unsigned long long writer = pwd_buffer->writer % PWD_BUFFER_SIZE;
        if (reader == writer) {
            continue;
        }
        char *pwd = pwd_buffer->buffer[reader];
        int validate_result = volatile_pwd_validate(argv[1], pwd);
        if (validate_result == -1) {
            printf("\033[31mError while validating password %s\033[0m\n", pwd_buffer->buffer[reader]);
        }
        else if (validate_result == 0) {
            printf("\033[31mInvalid password: %s\033[0m\n", pwd_buffer->buffer[reader]);
        }
        else {
            printf("\033[32mValid password: %s, %d file(s) passed\033[0m\n", pwd_buffer->buffer[reader], validate_result);
        }
        pwd_buffer->reader++;
        pwd_buffer->reader = pwd_buffer->reader % PWD_BUFFER_SIZE;
    }
    


    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(err));
    }
    cudaFree(d_data);
    printf("end\n");
}