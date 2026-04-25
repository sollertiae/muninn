#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <cstring>
#include <sodium.h>
#include <unistd.h>
#include <vector>
#include "commands.h"
#include "memory.h"
#include "log.h"
#include "vault.h"
#ifdef __APPLE__
    #include <sys/ptrace.h>
#elif __linux__
    #include <sys/prctl.h>
#endif

int main(int argc, char* argv[]) {
    #ifdef __APPLE__
        ptrace(PT_DENY_ATTACH, 0, 0, 0);
    #elif __linux__
        prctl(PR_SET_DUMPABLE, 0);
    #endif
    if (argc < 2) {
        std::cerr << "usage: muninn <command> [options]. use help to display commands.\n";
        return 1;
    }
    if (commands.count(argv[1])) {
        return commands[argv[1]].fn(argc, argv);
    }
    LOG_ERROR("unknown command: " << argv[1] << ". use help to display commands.");
    return 1;
}