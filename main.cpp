#include <iostream>
#include <sys/mman.h>
#include <csignal>
#include <unistd.h>
#include <strings.h>
#include <sodium.h>
#include <fstream>
#include "commands.h"
#include "memory.h"
#include "vault.h"


void handle_sigbus(int sig) {
    write(STDOUT_FILENO, "write attempt\n", 14);
    _exit(1);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: muninn <command> [options]. use help to display commands.\n";
        return 1;
    }
    if (commands.count(argv[1])) {
        return commands[argv[1]].fn(argc, argv);
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    const size_t MAX_ENTRIES = 64;
    signal(SIGBUS, handle_sigbus);
    
    vault v;
    if (!vault_init(&v, MAX_ENTRIES)) {
        return 1;
    }
    unsigned char* secure_buf = static_cast<unsigned char*>(secure_alloc(4096));
    char* password = reinterpret_cast<char*>(secure_buf);
    unsigned char* key = secure_buf + 128;
    std::cout << "Password: ";
    std::cin.getline(password, 127);
    
    vault_open(&v, password, "firstvault");
    // vault_add(&v);
    vault_debug(&v);
    vault_get(&v, "github");
    // vault_debug(&v);
    // vault_save(&v, key, salt, "firstvault");
    return 0;
}