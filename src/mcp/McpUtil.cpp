#include "mcp/McpUtil.h"

#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <cctype>

namespace area::mcp {

CmdResult exec(const std::string& workDir, const std::vector<std::string>& argv) {
    if (argv.empty()) return {"no command", -1};

    int pipefd[2];
    if (pipe(pipefd) < 0) return {"pipe() failed", -1};

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return {"fork() failed", -1};
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (!workDir.empty()) {
            if (chdir(workDir.c_str()) != 0) _exit(127);
        }
        std::vector<const char*> cargs;
        for (auto& a : argv) cargs.push_back(a.c_str());
        cargs.push_back(nullptr);
        execvp(cargs[0], const_cast<char**>(cargs.data()));
        _exit(127);
    }

    close(pipefd[1]);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) out.append(buf, n);
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return {out, WIFEXITED(status) ? WEXITSTATUS(status) : -1};
}

std::string trimOutput(std::string s, size_t maxLen) {
    if (s.size() > maxLen) s = "...\n" + s.substr(s.size() - maxLen);
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

bool isValidName(const std::string& s) {
    for (char c : s)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    return !s.empty();
}

}  // namespace area::mcp
