#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROOF_DIR "/srv/state/.arena-private/proofs"
#define HEALTH_PROOF_DIR "/srv/state/.arena-private/health-proofs"

static int valid_operation(const char *value) {
    size_t index;
    if (strlen(value) != 32) return 0;
    for (index = 0; index < 32; index++) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    struct passwd *account;
    struct stat info;
    char path[sizeof(HEALTH_PROOF_DIR) + 1 + 32];
    char buffer[512];
    ssize_t count;
    int descriptor;

    account = getpwnam("marimo");
    if (account == NULL || getuid() != account->pw_uid || argc != 2 || !valid_operation(argv[1])) {
        return 2;
    }
    if (snprintf(path, sizeof(path), "%s/%s", PROOF_DIR, argv[1]) >= (int)sizeof(path)) {
        return 2;
    }
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0 && errno == ENOENT) {
        if (snprintf(path, sizeof(path), "%s/%s", HEALTH_PROOF_DIR,
                     argv[1]) >= (int)sizeof(path)) {
            return 2;
        }
        descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    }
    if (descriptor < 0) return errno == ENOENT ? 4 : 3;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || info.st_nlink != 1 || (info.st_mode & 0777) != 0400) {
        close(descriptor);
        return 3;
    }
    while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)(count - offset));
            if (written < 0) {
                close(descriptor);
                return 3;
            }
            offset += written;
        }
    }
    close(descriptor);
    return count < 0 ? 3 : 0;
}
