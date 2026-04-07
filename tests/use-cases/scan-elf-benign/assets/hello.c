#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int add(int a, int b) {
    return a + b;
}

static void greet(const char* name) {
    printf("Hello, %s!\n", name);
}

int main(int argc, char** argv) {
    const char* name = "world";
    if (argc > 1) {
        name = argv[1];
    }
    greet(name);
    int result = add(40, 2);
    printf("The answer is %d\n", result);
    return 0;
}
