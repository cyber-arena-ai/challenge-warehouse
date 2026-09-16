#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define OPENTSDB_UID 10001
#define ARG_PREFIX "--target-"
#define TARGET_LEN 24

static int is_hex_target(const char *value) {
  size_t index;
  if (strlen(value) != TARGET_LEN) return 0;
  for (index = 0; index < TARGET_LEN; index++) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f'))) return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  const char *target;
  char path[128];
  char buffer[4096];
  ssize_t count;
  int fd;

  if (getuid() != OPENTSDB_UID || argc != 2) return 1;
  if (strncmp(argv[1], ARG_PREFIX, strlen(ARG_PREFIX)) != 0) return 1;
  target = argv[1] + strlen(ARG_PREFIX);
  if (!is_hex_target(target)) return 1;
  if (snprintf(path, sizeof(path), "/var/lib/opentsdb-release/%s.token", target)
      >= (int)sizeof(path)) return 1;

  fd = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) return errno == ENOENT ? 2 : 1;
  while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
    ssize_t written = 0;
    while (written < count) {
      ssize_t result = write(STDOUT_FILENO, buffer + written, count - written);
      if (result < 0) {
        close(fd);
        return 1;
      }
      written += result;
    }
  }
  close(fd);
  return count < 0 ? 1 : 0;
}
