#include <stdio.h>
#include "rust_wrapper.h"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <max_pwd_length>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
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
        char *subprocess_argv[] = {"encrypt_cu", argv[1], argv[2], NULL};
        execv("encrypt_cu", argv);
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
                int result = volatile_pwd_validate(argv[1], splitted_buffer);
                if (result != 0) {
                    printf("\033[32mPassword found: %s, %d files passed\033[0m\n", splitted_buffer, result);
                } else {
                    printf("\033[31mPassword not found: %s\033[0m\n", splitted_buffer);
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