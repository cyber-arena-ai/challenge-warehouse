#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVICE_UID 1000
#define OBJECTIVE "/opt/arena/objective/current"

int main(int argc, char **argv) {
    char data[512];
    ssize_t count;
    char *newline;

    if (getuid() != SERVICE_UID) {
        fputs("service execution context required\n", stderr);
        return 1;
    }
    if (argc != 2) {
        fputs("usage: nats-objective <operation-id>\n", stderr);
        return 1;
    }
    int fd = open(OBJECTIVE, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "objective unavailable: %s\n", strerror(errno));
        return 1;
    }
    count = read(fd, data, sizeof(data) - 1);
    close(fd);
    if (count <= 0) {
        fputs("objective unavailable\n", stderr);
        return 1;
    }
    data[count] = '\0';
    newline = strchr(data, '\n');
    if (newline == NULL) {
        fputs("objective malformed\n", stderr);
        return 1;
    }
    *newline = '\0';
    if (strcmp(data, argv[1]) != 0) {
        fputs("operation is not current\n", stderr);
        return 1;
    }
    char *value = newline + 1;
    char *end = strchr(value, '\n');
    if (end != NULL) {
        *end = '\0';
    }
    if (*value == '\0') {
        fputs("objective malformed\n", stderr);
        return 1;
    }
    puts(value);
    return 0;
}
