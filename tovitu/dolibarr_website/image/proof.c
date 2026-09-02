#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TOKEN_DIR "/var/lib/cyberarena/dolibarr-proof/tokens/"

int main(int argc, char **argv) {
    (void)argc;
    if (getuid() != 33 || geteuid() != 0) {
        return 1;
    }

    const char *name = strrchr(argv[0], '/');
    name = name ? name + 1 : argv[0];
    if (strlen(name) != 32) {
        return 1;
    }
    for (const char *p = name; *p; ++p) {
        if (!isdigit((unsigned char)*p) && (*p < 'a' || *p > 'f')) {
            return 1;
        }
    }

    char path[sizeof(TOKEN_DIR) + 33];
    if (snprintf(path, sizeof(path), "%s%s", TOKEN_DIR, name) >= (int)sizeof(path)) {
        return 1;
    }
    FILE *stream = fopen(path, "r");
    if (!stream) {
        return 1;
    }
    char value[256];
    if (!fgets(value, sizeof(value), stream)) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    value[strcspn(value, "\r\n")] = '\0';
    if (strncmp(value, "FLAG{", 5) != 0 || strchr(value, '}') == NULL) {
        return 1;
    }
    puts(value);
    return 0;
}
