#include <stdio.h>
#include <unistd.h>

int main(void) {
    puts("hello");
    printf("%d\n", (int)getpid());
    return 0;
}
