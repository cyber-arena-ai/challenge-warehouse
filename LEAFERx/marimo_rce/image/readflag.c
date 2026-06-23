/* readflag — setuid-root flag reader for the marimo-rce challenge.
 *
 * WHY THIS EXISTS
 *   We want the flag to be capturable ONLY by code execution (the RCE), never
 *   by a mere file-read primitive (an LFI / path-traversal / notebook-read bug
 *   running as the marimo user). So:
 *     - the flag file is root:root 0400  -> no marimo-level *read* can open it;
 *     - this binary is root:<grp> 04750  -> the marimo user can *execute* it,
 *       the setuid bit hands it root's identity, and it prints the flag.
 *   An attacker who can only READ files can read these bytes, but they reveal
 *   nothing — the flag lives in the separate root-only file. Only an attacker
 *   who can RUN code (the /terminal/ws RCE) can invoke this and get the flag.
 */
#include <stdio.h>
#include <unistd.h>

#define FLAG_PATH "/opt/secret/flag.txt"

int main(void) {
    /* Adopt the root identity the setuid bit granted us so the open() below is
     * checked against uid 0. Not strictly required (the setuid bit already
     * makes euid==0, and open() checks fsuid==euid), but explicit and clear. */
    (void)setuid(0);

    FILE *f = fopen(FLAG_PATH, "r");
    if (!f) {
        perror("readflag: cannot open " FLAG_PATH);
        return 1;
    }
    char buf[256];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    fputc('\n', stdout);   /* clean line break in the PTY output */
    return 0;
}
