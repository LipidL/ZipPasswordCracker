#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct local_file_header{
    u32 signature;
    u16 version_needed_to_extract;
    u16 general_purpose_bit_flag;
    u16 compression_method;
    u16 last_mod_file_time;
    u16 last_mod_file_date;
    u32 crc32;
    u32 compressed_size;
    u32 uncompressed_size;
    u16 file_name_length;
    u16 extra_field_length;
}__attribute__((packed));

struct aes_header{
    u16 signature;
    u16 data_size;
    u16 version_number;
    u8 vendor_id[2];
    u8 aes_encryption_strength;
    u16 compression_method;
}__attribute__((packed));
