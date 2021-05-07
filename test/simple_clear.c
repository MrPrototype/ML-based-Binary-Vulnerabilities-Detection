#include <stdio.h>
#include <errno.h> 
#include <limits.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
    int n, i, flag = 0;
    if (argc <= 1) exit(1);
    char *p;
    errno = 0;
    long conv = strtol(argv[1], &p, 10);
    if (errno != 0 || *p != '\0' || conv > INT_MAX || conv < INT_MIN) exit(1);
    else n = conv;
    for (i = 2; i <= n / 2; ++i) {
        if (n % i == 0) {
            flag = 1;
            break;
        }
    }
    if (n == 1) printf("1 is neither prime nor composite.\n");
    else {
        if (flag == 0) printf("%d is a prime number.\n", n);
        else printf("%d is not a prime number.\n", n);
    }
    return 0;
}