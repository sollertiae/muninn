#include <iostream>
#include <sys/mman.h>
#include <csignal>
#include <unistd.h>
#include <strings.h>
#include <functional>
#include <map>
#include <sodium.h>
#include <fstream>
#include "memory.h"
#include "vault.h"

using command_fn = std::function<int(int argc, char* argv[])>;

// std::map<std::string, command_fn> commands = {
//     {"create", cmd_create},
//     {"open",   cmd_open},
//     {"add",    cmd_add},
//     {"get",    cmd_get},
//     {"delete", cmd_delete},
//     {"list",   cmd_list}
// };

void handle_sigbus(int sig) {
    write(STDOUT_FILENO, "write attempt\n", 14);
    _exit(1);
}

int main(int argc, char* argv[]) {
    // if (argc < 2) {
    //     std::cerr << "usage: muninn <command> [options]. use help to display commands.\n";
    //     return 1;
    // }

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
    // if (crypto_pwhash(
    //     key, 
    //     crypto_box_SEEDBYTES, 
    //     password, 
    //     strlen(password), 
    //     salt, 
    //     crypto_pwhash_OPSLIMIT_INTERACTIVE,
    //     crypto_pwhash_MEMLIMIT_INTERACTIVE,
    //     crypto_pwhash_ALG_DEFAULT
    // ) < 0) {
    //     std::cout << "error deriving key" << "\n";
    //     return 1;
    // }
    vault_open(&v, password, "firstvault");
    // vault_add(&v);
    vault_debug(&v);
    vault_get(&v, "github");
    // vault_debug(&v);
    // vault_save(&v, key, salt, "firstvault");
    return 0;
}