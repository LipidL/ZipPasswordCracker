/* 
This CUDA algorithm is inspired by the `zip` crate from Rust.
The algorithm design and validation logic draw inspiration from the `zip` crate.
The `zip` crate can be found at https://crates.org.cn/crates/zip

The CUDA implementation here is original and written by LipidL.
*/


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
#include "toml.hpp"

#ifdef DEBUG
#define CHECK_CUDA(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error in %s at %s:%d: %s\n", \
            __func__, __FILE__, __LINE__, cudaGetErrorString(err)); \
        exit(EXIT_FAILURE); \
    } \
} while (0)
#else
#define CHECK_CUDA(call) call
#endif

#define debug(...) fprintf(stderr, __VA_ARGS__)

#define BLOCK_SIZE 64
#define MAX_PWD_LENGTH 64
#define PWD_BUFFER_SIZE 64
#define THREADS_PER_BLOCK 256

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
};

/**
 * @brief Calculate the length of a string
 * 
 * @param str The string to calculate the length of
 * @return The length of the string
 * 
 * @note The length of the string is calculated by counting the number of characters until the null terminator is reached.
 */
__device__ size_t device_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0' && len <= MAX_PWD_LENGTH) {
        len++;
    }
    return len;
}

/**
 * @brief Calculate the Message Authentication Code (MAC) using the HMAC-SHA1 algorithm
 * 
 * @param key The key to use in the HMAC-SHA1 algorithm
 * @param key_length The length of the key
 * @param data The data to use in the HMAC-SHA1 algorithm
 * @param hash The resulting hash from the HMAC-SHA1 algorithm
 * 
 * @return void
 * 
 * @note this function is a template function, specify the length of the data when calling it
 */
template <int DATA_LENGTH> __device__ void HMAC_SHA1(
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

/**
 * @brief Calculate the Password-Based Key Derivation Function 2 (PBKDF2) using the HMAC-SHA1 algorithm
 * 
 * @param password The password to use in the PBKDF2 algorithm
 * @param password_length The length of the password
 * @param salt The salt to use in the PBKDF2 algorithm
 * @param salt_length The length of the salt
 * @param iteration_count The number of iterations to use in the PBKDF2 algorithm
 * @param derived_key_length The length of the derived key
 * @param long_salt The space for saving the long salt while calculation
 * @param derived_key The resulting derived key from the PBKDF2 algorithm
 * 
 * @return void
 * 
 * @note the `long_salt` and `derived_key` region is modified in this function. `derived_key` is the final result, `long_salt` is used to store the variables during computation
 * @note the `long_salt` region is passed in as argument because allocation on device is prohibited on CUDA
 */
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

/**
 * @brief Check if a key is valid
 * 
 * @param key The key to check
 * @param key_length The length of the key
 * @param salt The salt to use in the PBKDF2 algorithm
 * @param salt_length The length of the salt
 * @param pwd_verification The password verification value
 * @param long_salt The region allocated for computing PBKDF2
 * @param first_part_1 The region allocated for computing HMAC_SHA1
 * @param first_part_2 The region allocated for computing HMAC_SHA1
 * @param second_part The region allocated for computing HMAC_SHA1
 * @param derived_key The derived key from the PBKDF2 algorithm
 * 
 * @return true if the key is valid, false otherwise
 * 
 * @note the `long_salt`, `first_part_1`, `first_part_2`, `second_part`, and `derived_key` regions are modified in this function, but their values is useless after the function returns
 * @note these regions pass in as arguments because allocation on device is prohibited on CUDA
 */
__device__ bool is_valid_key(u8 *key, u16 key_length, u8 *salt, u16 salt_length, u16 pwd_verification, u8 *long_salt, u8 *first_part_1, u8 *first_part_2, u8 *second_part, u8 *derived_key) {
    
    u64 derived_key_length = 2 * key_length + 2;
    PBKDF2_HMAC_SHA1(key, device_strlen((const char *)key), salt, salt_length, 1000, derived_key_length, long_salt, derived_key);
    if (derived_key[derived_key_length - 2] != (u8)((pwd_verification) & 0xFF) || derived_key[derived_key_length - 1] != (u8)((pwd_verification) >> 8)) {
        return false;
    }
    return true;
}

/**
 * @brief Add a number to a number represented as an array
 * 
 * @param test_pwd_num The number represented as an array
 * @param a The number to add
 * @param legal_chars_length The length of the legal characters, also the base of the number
 * 
 * @return The carry value after adding the number
 * 
 * @note If the carry value is not 0, overflow occurs
 */
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

/**
 * @brief Convert a number represented as an array to a string
 * 
 * @param test_pwd_num The number represented as an array
 * @param test_pwd The string to save the result
 * @param legal_chars The legal characters to use, also the converion table
 * 
 * @return void
 * 
 * @note The number represented as an array is terminated by -1
 */
__device__ void num_to_pwd(int64_t test_pwd_num[MAX_PWD_LENGTH], char *test_pwd, char *legal_chars)
{
    size_t len_legal_chars = device_strlen(legal_chars);
    for(size_t i = 0; i < MAX_PWD_LENGTH; i++){
        test_pwd[i] = '\0';
        if(test_pwd_num[i] == -1){
            break;
        }
        assert(i < len_legal_chars); // make sure the index is valid
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
            printf("%s\n",test_pwd);
        }
        if(add(test_pwd_num, data->num_threads, data->legal_chars_length) != 0){
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    // read config.toml
    toml::value config = toml::parse("config.toml");
    // parse the [file] table
    const toml::value &file_table = toml::find(config, "file");
    const std::string &file_format = toml::find<std::string>(file_table, "format");
    debug("file format: %s\n", file_format.c_str());
    assert(file_format == "zip"); // now we only support zip format
    const std::string &file_path = toml::find<std::string>(file_table, "path");
    debug("file path: %s\n", file_path.c_str());
    const std::string &encrypt_method = toml::find<std::string>(file_table, "encrypt_method");
    debug("encrypt method: %s\n", encrypt_method.c_str());
    assert(encrypt_method == "AES"); // now we only support AES encryption
    // parse the [password] table
    const toml::value &password_table = toml::find(config, "password");
    const bool digit = toml::find<bool>(password_table, "digit");
    const bool lower = toml::find<bool>(password_table, "lower");
    const bool upper = toml::find<bool>(password_table, "upper");
    const bool special = toml::find<bool>(password_table, "special");
    const u64 max_pwd_length = toml::find<u64>(password_table, "length");
    debug("digit: %d\n", digit);
    
    struct local_file_header *header;
    struct aes_header *aes_header;
    
    // open the file
    fprintf(stderr, "Opening file %s\n", file_path.c_str());
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    // get file size
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        exit(EXIT_FAILURE);
    }
    off_t size = st.st_size;
    void *file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    header = (struct local_file_header *)file;
    if (header->signature != 0x04034b50) {
        debug("Invalid signature\n");
        exit(EXIT_FAILURE);
    }
    else
        debug("Signature: 0x%08x\n", header->signature);
    if ((header->general_purpose_bit_flag & 0x1) != 0x1) {
        debug("File is not encrypted\n"); // encrypted files have the first bit set to 1
        exit(EXIT_FAILURE);
    }
    else    
        debug("File is encrypted\n");
    if (header->compression_method != 0x63) {
        debug("Invalid compression method\n"); // 0x63 is the AES encryption method (decimal 99)
        exit(EXIT_FAILURE);
    }
    uint64_t offset = sizeof(struct local_file_header) + header->file_name_length; // skip the header and the file name
    aes_header = (struct aes_header *)((char*)file + offset);   // sizeof(char) is always 1 according to C99 standard
                                                                // use this to walkaround the pointer arithmetic issue
    if (aes_header->signature != 0x9901) {
        debug("Invalid AES header signature\n");
        exit(EXIT_FAILURE);
    }
    if (aes_header->vendor_id[0] != 'A' || aes_header->vendor_id[1] != 'E') {
        debug("Invalid vendor ID\n");
        exit(EXIT_FAILURE);
    }
    if (aes_header->version_number != 0x0001 && aes_header->version_number != 0x0002){
        debug("Invalid AES encryption version\n");
        exit(EXIT_FAILURE);
    }
    u16 version = aes_header->version_number;
    if (version == 2 && header->crc32 ){
        debug("CRC32 should not present in AES-2 encrypted file\n");
        exit(EXIT_FAILURE);
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
    debug("salt_length is %d\n", salt_length);
    debug("key_length is %d\n", key_length);

    // find the number of GPU's multiprocessors
    int num_multiprocessors;
    cudaDeviceGetAttribute(&num_multiprocessors, cudaDevAttrMultiProcessorCount, 0);
    debug("num_multiprocessors: %d\n", num_multiprocessors);
    // calculate num_threads based on num_multiprocessors
    u64 num_threads = num_multiprocessors * THREADS_PER_BLOCK;

    // copy salt and pwd_verification to device
    u8 *d_salt, *d_pwd_verification;
    cudaMalloc((void**)&d_salt, salt_length * sizeof(char));
    cudaMalloc((void**)&d_pwd_verification, 2 * sizeof(char));
    cudaMemcpy(d_salt, salt, salt_length * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_pwd_verification, pwd_verification, 2 * sizeof(char), cudaMemcpyHostToDevice);

    // initialize legal_chars and legal_chars_length
    u64 legal_chars_length = 0;
    if (digit) {
        legal_chars_length += 10;
    }
    if (lower) {
        legal_chars_length += 26;
    }
    if (upper) {
        legal_chars_length += 26;
    }
    if (special) {
        legal_chars_length += 33;
    }
    char *legal_chars = (char*)malloc(legal_chars_length * sizeof(char));
    u64 index = 0;
    if (digit) {
        for (char c = '0'; c <= '9'; c++) {
            legal_chars[index++] = c;
        }
    }
    if (lower) {
        for (char c = 'a'; c <= 'z'; c++) {
            legal_chars[index++] = c;
        }
    }
    if (upper) {
        for (char c = 'A'; c <= 'Z'; c++) {
            legal_chars[index++] = c;
        }
    }
    if (special) {
        for (char c = '!'; c <= '/'; c++) {
            legal_chars[index++] = c;
        }
        for (char c = ':'; c <= '@'; c++) {
            legal_chars[index++] = c;
        }
        for (char c = '['; c <= '`'; c++) {
            legal_chars[index++] = c;
        }
        for (char c = '{'; c <= '~'; c++) {
            legal_chars[index++] = c;
        }
    }

    // copy legal_chars to device
    char *d_legal_chars;
    cudaMalloc((void**)&d_legal_chars, legal_chars_length * sizeof(char));
    cudaMemcpy(d_legal_chars, legal_chars, legal_chars_length * sizeof(char), cudaMemcpyHostToDevice);

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

    // copy data to device
    struct thread_data *d_data;
    cudaMalloc((void**)&d_data, sizeof(struct thread_data));
    cudaMemcpy(d_data, &data, sizeof(struct thread_data), cudaMemcpyHostToDevice);

    // configure thread and block size
    dim3 threads_per_block(THREADS_PER_BLOCK,1);
    dim3 num_blocks(num_multiprocessors, 1);
    debug("num_threads: %ld\n", num_threads);
    debug("threads_per_block: (%d, %d)\n", threads_per_block.x, threads_per_block.y);
    debug("num_blocks: (%d, %d)\n", num_blocks.x, num_blocks.y);
    assert(num_threads % threads_per_block.x == 0);
    assert(num_threads % threads_per_block.y == 0);

    // launch threads
    validate_key_thread<<<num_blocks, threads_per_block>>>(d_data);

    // synchronize
    cudaDeviceSynchronize();

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        debug("CUDA error: %s\n", cudaGetErrorString(err));
    }
    cudaFree(d_data);
    debug("end\n");
    exit(EXIT_SUCCESS);
}