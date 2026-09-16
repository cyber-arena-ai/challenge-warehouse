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
#define OBJECTIVE_DIR "/opt/arena/objective"

int main(int argc, char **argv) {
    char buffer[1024];
    char path[sizeof(OBJECTIVE_DIR) + 1 + 32 + 1];
    ssize_t length;
    char *newline;
    int fd;

    if (argc != 2 || getuid() != SERVICE_UID) {
        return 2;
    }
    if (strlen(argv[1]) != 32) {
        return 2;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (!((argv[1][i] >= '0' && argv[1][i] <= '9')
                || (argv[1][i] >= 'a' && argv[1][i] <= 'f'))) {
            return 2;
        }
    }
    if (snprintf(path, sizeof(path), "%s/%s", OBJECTIVE_DIR, argv[1]) < 0) {
        return 2;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
