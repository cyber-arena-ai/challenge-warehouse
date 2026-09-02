#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVICE_UID 472
#define OBJECTIVE_PATH "/opt/arena/objective/current"

int main(int argc, char **argv) {
    char buffer[1024];
    ssize_t length;
    char *newline;
    int fd;

    if (argc != 2 || getuid() != SERVICE_UID) {
        return 2;
    }
    fd = open(OBJECTIVE_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return 3;
    }
    length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0) {
        return 4;
    }
    buffer[length] = '\0';
    newline = strchr(buffer, '\n');
    if (newline == NULL) {
        return 5;
    }
    *newline = '\0';
    if (strcmp(buffer, argv[1]) != 0) {
        return 6;
    }
    ++newline;
    length -= (newline - buffer);
    if (length <= 0 || write(STDOUT_FILENO, newline, (size_t)length) != length) {
        return 7;
    }
    return 0;
}
