# ZipPasswordCracker

Welcome to ZipPasswordCracker, a powerful tool designed to crack passwords of encrypted zip files by traversing all possible password combinations.

## Features

+ **Multi-threaded CPU/GPU operations**: 
    + Leverage CUDA for GPU acceleration and multi-threading for CPU parallelism
    + Pipeline architecture for simutaneous GPU candidate generation and CPU validation
+ **Password character set support**:
    + *Numeric passwords*: Initial suport for numeric-only passwords (0-9).
    + *Expanded character sets*: Added support for letters (a-z, A-Z) and special characters.
+ **AES encryption compatibility**: Works with zip files encrypted using the AES method.
+ **Configuration file**: Customize settings via a `config.toml` file for seamless operation

## Build & Installation

# Prerequisites

+ **Compilers**:
    + `gcc` (GNU11 standard)
    + `g++` (C++20 standard)
    + `nvcc` (CUDA toolkit)
    + `cargo` (Rust compler for validation component)

+ **Steps**
    1. Clone the repository:
    ```bash
    git clone https://github.com/LipidL/ZipPasswordCracker
    cd ZipPasswordCracker
    ```

    2. Build the project
    ```bash
    make
    ```
    this will compile:
    + CUDA kernel for password candidate generation
    + C++ host code for pipeline management
    + Rust component (compiled to a dynamic library) for password validation


    3. Add the current directory to `$LD_LIBRARY_PATH` to make sure that the OS can load the compled dynamic library while running the program

    4. Configure settings in `config.toml`
    You can generate a default `config.toml` by running
    ```bash
    ./cracker_cuda init
    ```

    5.  Run the tool
    ```bash
    ./cracker_cuda
    ```
        
## Future Enhancements

We're constantly working to improve ZipPasswordCracker. Here are some features we're planning to add:

+ **7z support**: Extend cracking capabilities to 7z files.
+ **Progress bar**: Add a progress bar for real-time status monitoring.

## Technical Details

# Hybrid C++/Rust Implementation

+ The C++/CUDA core generates password candidates on the GPU.
+ A Rust comiled dynamic library validates candidates against the zip file using the `zip` crate.

# Dependencies

+ C++: Requires C++20 for template metaprogramming.
+ Rust: Uses the `zip` crate for validation
+ TOML Parsing: Uses `toml11` (C++ TOML library) for configuration

## Acknowledgement

This project uses the `zip` crate from Rust for validating passwords after CUDA validation. The `zip` crate can be found at [crates.io](https://crates.io/crates/zip).

This project also uses the `toml11` package for configuration file parsing. The `toml11` package can be found at [github](https://github.com/ToruNiina/toml11).