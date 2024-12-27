extern crate libc;
extern crate zip;
use libc::{c_char, c_int};
use zip::ZipArchive;
use std::fs;
use std::io;

#[no_mangle]
pub extern "C" fn volatile_pwd_validate(
    file_path: *const c_char,
    password: *const c_char,
) -> c_int {
    if file_path.is_null() || password.is_null() {
        return -1;
    }
    let file_path = unsafe { std::ffi::CStr::from_ptr(file_path) };
    let file_path = file_path.to_str().unwrap();
    let password = unsafe { std::ffi::CStr::from_ptr(password) };
    let password = password.to_str().unwrap();
    let file = fs::File::open(file_path).unwrap();

    let mut archive = ZipArchive::new(file).unwrap();
    let mut valid_pwd = 0;
    for i in 0..archive.len() {
        let mut file = match archive.by_index_decrypt(i, password.as_bytes()) {
            Ok(file) => file,
            Err(_) => return -1,
        };
        // try to extract the file to buffer
        let mut buffer = Vec::new();
        if let Ok(_) = io::copy(&mut file, &mut buffer) {
            valid_pwd += 1;
        } else {
            return valid_pwd;
        }
    }
    valid_pwd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_volatile_pwd_validate() {
        let file_path = CString::new("tests/test.zip").unwrap();
        let password = CString::new("123").unwrap();
        let result = volatile_pwd_validate(file_path.as_ptr(), password.as_ptr());
        assert_eq!(result, 1);
        let password = CString::new("1234").unwrap();
        let result = volatile_pwd_validate(file_path.as_ptr(), password.as_ptr());
        assert_eq!(result, 0);
        let password = CString::new("58130").unwrap();
        let result = volatile_pwd_validate(file_path.as_ptr(), password.as_ptr());
        assert_eq!(result, 1);
    }
}