/*
This program uses `toml11` to parse the `config.toml` file and read the file path and encryption method.
Then it forks itself and the child process runs the `encrypt_cu` program to generate the password.
The parent process reads the output from the child process and validates the password.
The output is colored in green if the password is valid and red if the password is invalid.
*/

#include <stdio.h>
#include "rust_wrapper.h"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "toml.hpp"

#define debug(...) fprintf(stderr, __VA_ARGS__)

int main(int argc, char *argv[]) {
    // debug("program start\n");
    if ((argc > 2) || ((argc == 2) && (strcmp(argv[1], "init") != 0) && (strcmp(argv[1], "default") != 0))) {
        debug("Usage: %s [default | init]\n", argv[0]);
        debug("%s: start parsing by using config.toml\n",argv[0]);
        debug("%s default: write a default config.toml and start cracking using the default configuration\n",argv[0]);
        debug("%s init: write a default config.toml and quit\n",argv[0]);
        exit(EXIT_FAILURE);
    }
    // debug("argc: %d\n", argc);
    if ((argc == 2) && ((strcmp(argv[1], "init") == 0) || (strcmp(argv[1], "default") == 0))) {
        // write default config.toml
        FILE *fp = fopen("config.toml", "w");
        if (fp == NULL) {
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        fprintf(fp, "[file]\n");
        fprintf(fp, "format = \"zip\"\n");
        fprintf(fp, "path = \"test.zip\"\n");
        fprintf(fp, "encrypt_method = \"AES\"\n");
        fprintf(fp, "[password]\n");
        fprintf(fp, "digit = true\n");
        fprintf(fp, "lower = false\n");
        fprintf(fp, "upper = false\n");
        fprintf(fp, "special = false\n");
        fprintf(fp, "length = 6\n");
        fclose(fp);
        if (strcmp(argv[1], "init") == 0){
            exit(EXIT_SUCCESS);
        }
    } 
    debug("Start parsing config.toml\n");
    // parse the config.toml for file path
    toml::value config = toml::parse("config.toml");
    const toml::value &file_table = toml::find(config, "file");
    const std::string &file_format = toml::find<std::string>(file_table, "format");
    debug("file format: %s\n", file_format.c_str());
    assert(file_format == "zip"); // now we only support zip format
    const std::string &file_path = toml::find<std::string>(file_table, "path");
    debug("file path: %s\n", file_path.c_str());
    const std::string &encrypt_method = toml::find<std::string>(file_table, "encrypt_method");
    debug("encrypt method: %s\n", encrypt_method.c_str());
    assert(encrypt_method == "AES"); // now we only support AES encryption
    // initialize a pipe
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // fork itself
    int pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // child process, run the cuda program
        // redirect the stdout to the write end of the pipe
        close(pipefd[0]); // close unused read end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]); // close write end after duplicating
        printf("Child process\n");
        // execute the cuda program
        char *subprocess_argv[] = {(char*)"encrypt_cu", NULL};
        execv("encrypt_cu", subprocess_argv);
    } else {
        // parent process
        // redirect the read end of the pipe to stdin
        close(pipefd[1]); // close unused write end
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]); // close read end after duplicating

        // read the output from the pipe
        char buffer[1];
        char splitted_buffer[1024] = {0};
        int splitted_buffer_reader = 0;
        char full_buffer[1024] = {0};
        int full_buffer_reader = 0;
        while (1) {
            int n = read(STDIN_FILENO, buffer, 1); // read one byte at a time
            if (n == 0) {
                // check if the child process has terminated
                int status;
                if (waitpid(pid, &status, WNOHANG) == pid) {
                    break;
                } else {
                    continue;
                }
            } else if (n == -1) {
                perror("read");
                return 1;
            }
            if (buffer[0] == '\n') {
                // split the buffer
                splitted_buffer[splitted_buffer_reader] = '\0';
                splitted_buffer_reader = 0;
                // validate the password
                int result = volatile_pwd_validate(file_path.c_str(), splitted_buffer);
                if (result != 0 && result != -1) {
                    printf("\033[32mValid password: %s, %d files passed\033[0m\n", splitted_buffer, result);
                } else {
                    printf("\033[31mInvalid password: %s\033[0m\n", splitted_buffer);
                }
                // clear the splitted buffer
                memset(splitted_buffer, 0, sizeof(splitted_buffer));
            } else {
                splitted_buffer[splitted_buffer_reader++] = buffer[0];
            }
        }
        return 0;
    }
}