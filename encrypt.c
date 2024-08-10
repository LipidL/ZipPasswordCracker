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
#include <math.h>
#include "sha1.h"

#define BLOCK_SIZE 64
#define MAX_PWD_LENGTH 10
#define NUM_THREADS 10

struct thread_data{
    u16 key_length;
    u8 *salt;
    u16 salt_length;
    u16 pwd_verification;
    u64 pwd_length; // maximum password length
    char *legal_chars;
    u64 legal_chars_length;
    u64 thread_id;
    u64 num_threads;
};

struct legal_pwds{
    char pwd[MAX_PWD_LENGTH];
    u16 pwd_length;
    struct legal_pwds *next;
    pthread_mutex_t mutex;
};

struct pwd_list{
    struct legal_pwds *first;
    struct legal_pwds *last;
    pthread_mutex_t mutex;
};

struct pwd_list pwd_list = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER};

void HMAC_SHA1(
    unsigned char *key, uint64_t key_length,
    unsigned char *data, uint64_t data_length,
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
    unsigned char *first_part = malloc(BLOCK_SIZE + data_length);
    memcpy(first_part, i_key_pad, BLOCK_SIZE);
    memcpy(first_part + BLOCK_SIZE, data, data_length);

    sha1(first_part, BLOCK_SIZE + data_length, first_hash);
    free(first_part);

    unsigned char *second_part = malloc(BLOCK_SIZE + 20);
    memcpy(second_part, o_key_pad, BLOCK_SIZE);
    memcpy(second_part + BLOCK_SIZE, first_hash, 20);

    sha1(second_part, BLOCK_SIZE + 20, hash);
    free(second_part);
}

void PBKDF2_HMAC_SHA1(unsigned char *password, uint64_t password_length,
                      unsigned char *salt, uint64_t salt_length,
                      uint64_t iteration_count, uint64_t derived_key_length,
                      unsigned char *derived_key) {
    u64 i, j, k, blocks;
    u8 hash[20], previous_hash[20], xor_hash[20], salt_ipad[64], salt_opad[64];
    u8 *long_salt = malloc(salt_length + 4);
    memset(long_salt, 0, salt_length + 4);
    memcpy(long_salt, salt, salt_length);
    blocks = (derived_key_length + 19) / 20;

    for (i = 0; i < blocks; i++) {
        long_salt[salt_length] = ((i + 1) >> 24) & 0xFF;
        long_salt[salt_length + 1] = ((i + 1) >> 16) & 0xFF;
        long_salt[salt_length + 2] = ((i + 1) >> 8) & 0xFF;
        long_salt[salt_length + 3] = (i + 1) & 0xFF;

        HMAC_SHA1(password, password_length, long_salt, salt_length + 4, previous_hash);

        memcpy(xor_hash, previous_hash, 20);

        for (j = 1; j < iteration_count; j++) {
            HMAC_SHA1(password, password_length, previous_hash, 20, hash);
            memcpy(previous_hash, hash, 20);

            for (k = 0; k < 20; k++) {
                xor_hash[k] ^= hash[k];
            }
        }

        memcpy(derived_key + i * 20, xor_hash, (i == blocks - 1 && derived_key_length % 20) ? derived_key_length % 20 : 20);
    }
}

bool is_valid_key(u8 *key, u16 key_length, u8 *salt, u16 salt_length, u16 pwd_verification) {
    u64 derived_key_length = 2 * key_length + 2;
    u8 *derived_key = malloc(derived_key_length);
    PBKDF2_HMAC_SHA1(key, strlen((const char *)key), salt, salt_length, 1000, derived_key_length, derived_key);
    if (derived_key[derived_key_length - 2] != (u8)((pwd_verification) & 0xFF) || derived_key[derived_key_length - 1] != (u8)((pwd_verification) >> 8)) {
        return false;
    }
    return true;
}

u8 add(int64_t test_pwd_num[MAX_PWD_LENGTH], u64 a, u64 legal_chars_length)
{
    // add test_pwd_num by a
    u8 carry = 0;
    int64_t add_result = test_pwd_num[0] + a;
    test_pwd_num[0] = add_result % legal_chars_length;
    carry = add_result / legal_chars_length;
    for(size_t i = 1; i < MAX_PWD_LENGTH; i++){
        if(carry == 0)
            break;
        test_pwd_num[i] = (test_pwd_num[i] + carry) % legal_chars_length;
        carry = (test_pwd_num[i] + carry) / legal_chars_length;
    }
    return carry;
}

void num_to_pwd(int64_t test_pwd_num[MAX_PWD_LENGTH], char *test_pwd, char *legal_chars)
{
    for(size_t i = 0; i < MAX_PWD_LENGTH; i++){
        test_pwd[i] = '\0';
        if(test_pwd_num[i] == -1){
            break;
        }
        test_pwd[i] = legal_chars[test_pwd_num[i]];
    }
}

void insert_valid_pwd(char *pwd)
{
    struct legal_pwds *node = (struct legal_pwds *)malloc(sizeof(struct legal_pwds));
    strcpy(node->pwd, pwd);
    node->pwd_length = strlen(pwd);
    pthread_mutex_init(&(node->mutex), NULL);
    pthread_mutex_lock(&(pwd_list.mutex));
    node->next = pwd_list.first;
    pwd_list.first = node;
    if (pwd_list.last == NULL){
        pwd_list.last = node;
    }
    pthread_mutex_unlock(&(pwd_list.mutex));
}

void validate_key_thread(struct thread_data *data)
{
    printf("thread %ld created\n", data->thread_id);
    int64_t test_pwd_num[MAX_PWD_LENGTH];
    for (size_t i = 0; i < MAX_PWD_LENGTH; i++){
        test_pwd_num[i] = -1;
    }
    char test_pwd[MAX_PWD_LENGTH + 1];
    for(size_t i = 0; i < MAX_PWD_LENGTH + 1; i++){
        test_pwd[i] = '\0';
    }
    // initialize thread pwd
    if(add(test_pwd_num, data->thread_id, data->legal_chars_length) != 0){
        return;
    }
    long double count = powl(data->legal_chars_length + 1, data->pwd_length) / data->num_threads;
    for(size_t i = 0; i < count; i++){
        num_to_pwd(test_pwd_num, test_pwd, data->legal_chars);
        if(strlen(test_pwd) > data->pwd_length){
            return;
        }
        if(is_valid_key((u8*)test_pwd, data->key_length, data->salt, data->salt_length, data->pwd_verification)){
            insert_valid_pwd(test_pwd);
            printf("\033[1;32m valid pwd found: %s  \033[0m \n",test_pwd);
        }
        else{
            printf("\033[1;31m invalid pwd: %s  \033[0m \n",test_pwd);
        }
        if(add(test_pwd_num, data->num_threads, data->legal_chars_length) != 0){
            return;
        }
    }

}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }
    
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
    else
        printf("Compression method: 0x%04x\n", header->compression_method);
    uint64_t offset = sizeof(struct local_file_header) + header->file_name_length; // skip the header and the file name
    printf("Offset: %lu = %lu + %u\n", offset, sizeof(struct local_file_header), header->file_name_length);
    aes_header = (struct aes_header *)(file + offset);
    if (aes_header->signature != 0x9901) {
        printf("Invalid AES header signature\n");
        return 1;
    }
    else
        printf("AES header signature: 0x%04x\n", aes_header->signature);
    if (aes_header->vendor_id[0] != 'A' || aes_header->vendor_id[1] != 'E') {
        printf("Invalid vendor ID\n");
        return 1;
    }
    else
        printf("Vendor ID: %c%c\n", aes_header->vendor_id[0], aes_header->vendor_id[1]);
    if (aes_header->version_number != 0x0001 && aes_header->version_number != 0x0002){
        printf("Invalid AES encryption version\n");
        return 1;
    }
    else
        printf("AES encryption version: 0x%04x\n", aes_header->version_number);
    u16 version = aes_header->version_number;
    if (version == 2 && header->crc32 ){
        printf("CRC32 should not present in AES-2 encrypted file\n");
        return 1;
    }
    // extract AES encryption strength
    // AES-128 = 1, AES-192 = 2, AES-256 = 3
    u16 aes_encryption_strength;
    u8 salt_length;
    switch (aes_header->aes_encryption_strength){
    case 1:
        aes_encryption_strength = 128;
        salt_length = 8;
        break;
    case 2:
        aes_encryption_strength = 192;
        salt_length = 12;
        break;
    case 3:
        aes_encryption_strength = 256;
        salt_length = 16;
        break;
    default:
        assert(0); // should never happen
    }
    u16 key_length = salt_length * 2;
    printf("AES encryption strength: %d bits\n", aes_encryption_strength);
    printf("Salt length: %d bytes\n", salt_length);
    u8 *salt = (u8 *)(file + offset + sizeof(struct aes_header));
    u16 *pwd_verification = (u16 *)(salt + salt_length);
    printf("Password verification: 0x%04x\n", *pwd_verification);
    printf("Salt: ");
    for (int i = 0; i < salt_length; i++)
        printf("%02x", salt[i]);
    printf("\n");
    
    // derive key and check password
    printf("%d\n",is_valid_key((u8 *)"54321", key_length, salt, salt_length, *pwd_verification));

    // test pwd traversal
    char *legal_chars = malloc(10 * sizeof(char));
    for(size_t i = 0; i < 10; i++){
        legal_chars[i] = '0' + i;
    }

    // construct threads
    pthread_t threads[NUM_THREADS];
    struct thread_data data[NUM_THREADS];
    for (size_t i = 0; i < NUM_THREADS; i++){
        data[i].key_length = key_length;
        data[i].legal_chars = legal_chars;
        data[i].legal_chars_length = 10;
        data[i].num_threads = NUM_THREADS;
        data[i].pwd_length = 5;
        data[i].pwd_verification = *pwd_verification;
        data[i].salt = salt;
        data[i].salt_length = salt_length;
        data[i].thread_id = i;
        pthread_create(&threads[i], NULL, (void *)validate_key_thread, &data[i]);
    }
    for(size_t i = 0; i < NUM_THREADS; i++){
        pthread_join(threads[i], NULL);
    }
    struct legal_pwds *node = pwd_list.first;
    while(node != NULL){
        printf("possible pwd: %s\n", node->pwd);
        node = node->next;
    } 
    // int64_t test_pwd_num[MAX_PWD_LENGTH];
    // for (size_t i = 0; i < MAX_PWD_LENGTH; i++){
    //     test_pwd_num[i] = -1;
    // }
    
    // char test_pwd[MAX_PWD_LENGTH + 1] = {"\0"};
    // for(size_t i = 0; i < powl(10, 5); i++){
    //     if(add(test_pwd_num, 1, 10) != 0)
    //         break;
    //     num_to_pwd(test_pwd_num, test_pwd, legal_chars);
    //     if(is_valid_key((u8 *)test_pwd, key_length, salt, salt_length, *pwd_verification)){
    //         printf("\033[1;32m valid pwd found: %s  \033[0m \n",test_pwd);
    //     }
    //     else{
    //         printf("\033[1;31m invalid pwd: %s  \033[0m \n",test_pwd);
    //     }
    // }
    // return 0;
}