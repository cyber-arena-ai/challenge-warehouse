#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *prefix = "nv-proof-";
    const char *base = strrchr(argv[0], '/');
    char path[PATH_MAX];
    char value[256];
    ssize_t count;
    int fd;
    (void)argc;

    base = base ? base + 1 : argv[0];
    if (getuid() != 33 || strncmp(base, prefix, strlen(prefix)) != 0) {
        return 1;
    }
    const char *id = base + strlen(prefix);
    if (strlen(id) != 24 || strspn(id, "0123456789abcdef") != 24) {
        return 1;
    }
    if (snprintf(path, sizeof(path), "/run/navigate-proof/%s.token", id) >= (int)sizeof(path)) {
        return 1;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return 1;
    }
    count = read(fd, value, sizeof(value));
    close(fd);
    if (count <= 0 || write(STDOUT_FILENO, value, (size_t)count) != count) {
        return 1;
    }
    return 0;
}
