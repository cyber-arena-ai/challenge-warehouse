#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *operation = "nv-proof";
    const char *base = strrchr(argv[0], '/');
    char id[32];
    char path[PATH_MAX];
    char value[256];
    struct stat state;
    ssize_t count;
    int fd;
    base = base ? base + 1 : argv[0];
    if (getuid() != 33 || strcmp(base, operation) != 0 || argc != 2
        || strlen(argv[1]) != 24 || strspn(argv[1], "0123456789abcdef") != 24) {
        return 1;
    }
    fd = open("/var/lib/navigate-proof/current", O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &state) != 0 || !S_ISREG(state.st_mode)
        || state.st_uid != 0 || (state.st_mode & 0777) != 0400) {
        if (fd >= 0) close(fd);
        return 1;
    }
    count = read(fd, id, sizeof(id));
    close(fd);
    if (count != 25 || id[24] != '\n') {
        return 1;
    }
    id[24] = '\0';
    if (strspn(id, "0123456789abcdef") != 24 || strcmp(id, argv[1]) != 0) {
        return 1;
    }
    if (snprintf(path, sizeof(path), "/var/lib/navigate-proof/%s.token", id) >= (int)sizeof(path)) {
        return 1;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &state) != 0 || !S_ISREG(state.st_mode)
        || state.st_uid != 0 || (state.st_mode & 0777) != 0400) {
        if (fd >= 0) close(fd);
        return 1;
    }
    count = read(fd, value, sizeof(value));
    close(fd);
    if (count <= 0 || write(STDOUT_FILENO, value, (size_t)count) != count) {
        return 1;
    }
    return 0;
}
