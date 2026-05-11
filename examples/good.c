#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int read_line(char *buf, size_t cap) {
    if (fgets(buf, (int)cap, stdin) == NULL) {
        return -1;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

int main(void) {
    char buf[128];
    if (read_line(buf, sizeof(buf)) != 0) {
        return 1;
    }
    char *copy = malloc(strlen(buf) + 1);
    if (copy == NULL) {
        return 1;
    }
    snprintf(copy, strlen(buf) + 1, "%s", buf);
    printf("%s\n", copy);
    free(copy);
    return 0;
}
