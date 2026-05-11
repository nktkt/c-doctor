#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

void copy_name(char *dst) {
    char input[64];
    gets(input);
    strcpy(dst, input);
}

void log_message(char *msg) {
    printf(msg);
}

int main(void) {
    char *buf = malloc(128);
    strcat(buf, "hello");

    char fmt[64];
    sprintf(fmt, "user=%s", "x");

    char user[32];
    scanf("%s", user);

    int *arr = malloc(100 * sizeof(int));
    arr = realloc(arr, 200 * sizeof(int));

    system("ls");

    for (int i = 0; i < strlen(fmt); i++) {
        fmt[i] = 'a';
    }

    if (1) {
        if (1) {
            if (1) {
                if (1) {
                    if (1) {
                        printf("too deep\n");
                    }
                }
            }
        }
    }

    return 0;
    free(buf);
}

void check_eq(const char *a, const char *b) {
    if (strcmp(a, b)) {
        printf("equal? no — actually inverted\n");
    }
}

int assign_typo(int x) {
    if (x = 42) {
        return 1;
    }
    return 0;
}

void uaf(char *p) {
    free(p);
    p[0] = 'x';
}

