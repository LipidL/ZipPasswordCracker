#ifndef RUST_WRAPPER_H
#define RUST_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

int volatile_pwd_validate(const char *file_path, const char *password);

#ifdef __cplusplus
}
#endif

#endif // RUST_WRAPPER_H