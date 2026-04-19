#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <strings.h>
#include <sodium.h>
#include <fstream>
#include "commands.h"
#include "memory.h"
#include "vault.h"
#include <sys/ptrace.h>

int main(int argc, char* argv[]) {
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    if (argc < 2) {
        std::cerr << "usage: muninn <command> [options]. use help to display commands.\n";
        return 1;
    }
    if (commands.count(argv[1])) {
        return commands[argv[1]].fn(argc, argv);
    }
    return 0;
}