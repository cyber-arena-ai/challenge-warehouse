/*
 * catflag — the challenge's service-context-only helper operation.
 *
 * The current round's operation id and its proof live in a root-owned 0600 file
 * under a 0700 directory, so no ordinary file read and no file write recovers
 * the proof. This helper is the only way out, and it answers only when its real
 * uid is the Apache service account and the caller names the current operation.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVICE_UID 33 /* www-data */
#define OBJECTIVE_PATH "/var/lib/arena/command/objective"

int main(int argc, char **argv)
{
    char buf[1024];
    if (argc != 2 || getuid() != SERVICE_UID) return 2;
    int fd = open(OBJECTIVE_PATH, O_RDONLY);
    if (fd < 0) return 3;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 4;
    buf[n] = '\0';
    char *flag = strchr(buf, '\n');
    if (flag == NULL) return 5;
    *flag++ = '\0';
    flag[strcspn(flag, "\r\n")] = '\0';
    if (strcmp(argv[1], buf) != 0 || *flag == '\0') return 6;
    puts(flag);
    return 0;
}
