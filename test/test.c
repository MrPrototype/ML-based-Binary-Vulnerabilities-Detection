#include <stdio.h>
#include <strings.h>

void execs(void) {
    printf("yay!!");
}

void return_input (void) {
    char array[30];
    gets(array);
}

int main() {
    return_input();
    return 0;
}