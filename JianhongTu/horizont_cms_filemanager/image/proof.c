#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVICE_UID 33

static int valid_locator(const char *value) {
    size_t length = strlen(value);
    if (length != 24) return 0;
    for (size_t index = 0; index < length; index++) {
        char current = value[index];
        if (!((current >= '0' && current <= '9') ||
              (current >= 'a' && current <= 'f'))) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    char path[128];
    char buffer[512];
    ssize_t count;

    if (argc != 2 || getuid() != SERVICE_UID || geteuid() != 0 ||
        !valid_locator(argv[1])) return 2;
    if (snprintf(path, sizeof(path), "/var/lib/horizont/proofs/%s", argv[1]) >=
        (int)sizeof(path)) return 3;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 4;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0) {
        close(fd);
        return 5;
    }
    count = read(fd, buffer, sizeof(buffer));
    close(fd);
    if (count <= 0 || write(STDOUT_FILENO, buffer, (size_t)count) != count) return 6;
    return 0;
}
