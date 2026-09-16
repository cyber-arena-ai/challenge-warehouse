/* catflag — the command objective's fixed helper.
 *
 * Root-owned, setuid, callable only by the Grav service account (UID 1001).
 * The current round's objective lives in one root-only file holding two lines:
 *
 *     <operation-id>\n<flag>\n
 *
 * The helper prints the flag only when its single argument is the current
 * operation id.  Nothing else on the box can read the backing file: the file is
 * 0600 root:root inside a 0700 root:root directory, so a direct read by UID 1001
 * fails and running this helper in the service execution context is the only way
 * to the value.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVICE_UID 1001
#define OBJECTIVE_PATH "/var/lib/arena/command/objective"

/* Read the objective file into buf; split it at the first newline.  Returns 0 on
 * success and leaves *op / *flag pointing into buf. */
static int read_objective(char *buf, size_t cap, char **op, char **flag)
{
    int fd = open(OBJECTIVE_PATH, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    char *split = strchr(buf, '\n');
    if (split == NULL) {
        return -1;
    }
    *split = '\0';
    *op = buf;
    *flag = split + 1;
    /* trim the trailing newline(s) the writer leaves on the flag line */
    size_t len = strlen(*flag);
    while (len > 0 && ((*flag)[len - 1] == '\n' || (*flag)[len - 1] == '\r')) {
        (*flag)[--len] = '\0';
    }
    return (**op == '\0' || **flag == '\0') ? -1 : 0;
}

int main(int argc, char **argv)
{
    char buf[1024];
    char *op = NULL;
    char *flag = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: catflag <operation-id>\n");
        return 2;
    }
    if (getuid() != SERVICE_UID) {
        fprintf(stderr, "catflag: only the service account may run this helper\n");
        return 3;
    }
    if (read_objective(buf, sizeof buf, &op, &flag) != 0) {
        fprintf(stderr, "catflag: no current operation\n");
        return 4;
    }
    if (strcmp(argv[1], op) != 0) {
        fprintf(stderr, "catflag: not the current operation id\n");
        return 5;
    }
    puts(flag);
    return 0;
}
