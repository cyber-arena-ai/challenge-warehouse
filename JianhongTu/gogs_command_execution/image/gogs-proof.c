#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct passwd *account;
    char path[128];
    char buffer[4096];
    ssize_t count;
    int fd;
    size_t index;

    account = getpwnam("arena_agent");
    if (account == NULL || getuid() != account->pw_uid || argc != 2 || strlen(argv[1]) != 32) {
        return 2;
    }
    for (index = 0; index < 32; index++) {
        if (!((argv[1][index] >= '0' && argv[1][index] <= '9') ||
              (argv[1][index] >= 'a' && argv[1][index] <= 'f'))) {
            return 2;
        }
    }
    if (snprintf(path, sizeof(path), "/var/lib/cyberarena-exec/%s", argv[1]) >= (int)sizeof(path)) {
        return 2;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? 4 : 3;
    }
    count = read(fd, buffer, sizeof(buffer));
    if (count <= 0 || write(STDOUT_FILENO, buffer, (size_t)count) != count) {
        close(fd);
        return 3;
    }
    close(fd);
    return 0;
}
