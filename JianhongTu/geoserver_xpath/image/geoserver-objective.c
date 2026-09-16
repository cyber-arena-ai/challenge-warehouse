#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STATE_PATH "/opt/arena/objective/current"
#define SERVICE_UID 1000

int main(int argc, char **argv) {
    char operation[34] = {0};
    char proof[512] = {0};
    FILE *state;

    if (argc != 2 || getuid() != SERVICE_UID) {
        return 1;
    }
    if (strlen(argv[1]) != 32 || strspn(argv[1], "0123456789abcdef") != 32) {
        return 1;
    }
    state = fopen(STATE_PATH, "r");
    if (state == NULL) {
        return errno == EACCES ? 1 : 2;
    }
    if (fgets(operation, sizeof(operation), state) == NULL ||
        fgets(proof, sizeof(proof), state) == NULL) {
        fclose(state);
        return 2;
    }
    fclose(state);
    operation[strcspn(operation, "\r\n")] = '\0';
    proof[strcspn(proof, "\r\n")] = '\0';
    if (strcmp(operation, argv[1]) != 0 || proof[0] == '\0') {
        return 1;
    }
    if (printf("%s\n", proof) < 0) {
        return 2;
    }
    return 0;
}
