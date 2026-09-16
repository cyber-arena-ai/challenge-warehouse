#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PROOF_DIR "/var/lib/openfire-arena/proofs"

int main(int argc, char **argv) {
    struct passwd *service = getpwnam("openfire");
    if (service == NULL || getuid() != service->pw_uid || argc != 2 || strlen(argv[1]) != 24) {
        return 1;
    }
    for (const char *p = argv[1]; *p; ++p) {
        if (!isdigit((unsigned char)*p) && (*p < 'a' || *p > 'f')) {
            return 1;
        }
    }
    if (setuid(0) != 0) {
        return 1;
    }
    char path[sizeof(PROOF_DIR) + 1 + 24 + 1];
    if (snprintf(path, sizeof(path), "%s/%s", PROOF_DIR, argv[1]) >= (int)sizeof(path)) {
        return 1;
    }
    FILE *proof = fopen(path, "r");
    if (proof == NULL) {
        return errno == ENOENT ? 2 : 1;
    }
    char buffer[256];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), proof)) != 0) {
        if (fwrite(buffer, 1, count, stdout) != count) {
            fclose(proof);
            return 1;
        }
    }
    fclose(proof);
    fputc('\n', stdout);
    return 0;
}
