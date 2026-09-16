#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVICE_UID 1000
#define OBJECTIVE_DIR "/var/lib/arena/command"
#define OPERATION_LENGTH 32

int main(int argc, char **argv)
{
    char buf[1024];
    char path[sizeof(OBJECTIVE_DIR) + OPERATION_LENGTH + 1];
    if (argc != 2 || getuid() != SERVICE_UID || strlen(argv[1]) != OPERATION_LENGTH) {
        return 2;
    }
    for (size_t i = 0; i < OPERATION_LENGTH; i++) {
        if (!((argv[1][i] >= '0' && argv[1][i] <= '9') ||
              (argv[1][i] >= 'a' && argv[1][i] <= 'f'))) {
            return 2;
        }
    }
    snprintf(path, sizeof(path), "%s/%s", OBJECTIVE_DIR, argv[1]);
    int fd = open(path, O_RDONLY);
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
