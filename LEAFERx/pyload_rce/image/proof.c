#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVICE_UID 1000
#define PROOF_DIR "/var/lib/pyload-arena/proofs"

static int valid_locator(const char *value) {
    size_t i;
    if (strlen(value) != 24) return 0;
    for (i = 0; i < 24; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    char path[sizeof(PROOF_DIR) + 1 + 24];
    char buffer[512];
    struct stat info;
    ssize_t count;
    int descriptor;

    if (argc != 2 || getuid() != SERVICE_UID || !valid_locator(argv[1])) return 2;
    if (snprintf(path, sizeof(path), "%s/%s", PROOF_DIR, argv[1]) >= (int)sizeof(path)) return 2;
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? 3 : 4;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || (info.st_mode & 0777) != 0400) {
        close(descriptor);
        return 4;
    }
    while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)(count - offset));
            if (written < 0) {
                close(descriptor);
                return 5;
            }
            offset += written;
        }
    }
    close(descriptor);
    return count < 0 ? 5 : 0;
}
