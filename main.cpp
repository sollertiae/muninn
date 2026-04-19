#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <strings.h>
#include <sodium.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include "commands.h"
#include "memory.h"
#include "log.h"
#include "vault.h"

int main(int argc, char* argv[]) {
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
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