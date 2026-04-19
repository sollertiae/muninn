#include <iostream>
#include <sys/mman.h>
#include <csignal>
#include <unistd.h>
#include <sodium.h>
#include <strings.h>
#include <functional>
#include <map>
#include <fstream>

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

struct secret_entry {
    char key[128];
    char value[512];
    bool active;
};

struct vault {
    secret_entry* entries;
    void* raw_memory;
    size_t max_entries;
    size_t memory_size;
};

void* secure_alloc(size_t size) {
    void* ptr = mmap(
            nullptr, 
            size, 
            PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANONYMOUS, 
            -1, 
            0
        );
    if (ptr == MAP_FAILED) {
        return nullptr;
    }
    if (mlock(ptr, size) != 0) {
        std::cerr << "mlock failed\n";
        munmap(ptr, size);
        return nullptr;
    }
    return ptr;
}

void secure_seal(void* ptr, size_t size) {
    mprotect(ptr, size, PROT_READ);
    std::cout << "memory is now read-only\n";
}

void secure_unseal(void* ptr, size_t size) {
    mprotect(ptr, size, PROT_READ | PROT_WRITE);
    std::cout << "memory is now read-write\n";   
}

void secure_free(void* ptr, size_t size) {
    secure_unseal(ptr, size);
    sodium_memzero(ptr, size);
    munmap(ptr, size);
}

bool vault_init(vault *v, size_t max_entries) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return false;
    }
    size_t size = sizeof(secret_entry) * max_entries;
    void* ptr = secure_alloc(size);
    if (!ptr) {
        std::cerr << "allocation failed\n";
        return false;
    }
    sodium_memzero(ptr, size);
    v->entries = static_cast<secret_entry*>(ptr);
    v->raw_memory = ptr;
    v->memory_size = size;
    v->max_entries = max_entries;
    return true;
}

void vault_debug(vault* v) {
    std::cout << "\n--- vault print---\n";
    for (size_t i = 0; i < v->max_entries; ++i) {
        if (v->entries[i].active) {
            std::cout << "slot " << i << ": " << v->entries[i].key << " -> " << v->entries[i].value << "\n";
        }
    }
}

bool vault_add(vault* v) {
    for (size_t i = 0; i < v->max_entries; ++i) {
        if (!v->entries[i].active) {
            std::cout << "enter key: ";
            std::cin.getline(v->entries[i].key, 127);
            std::cout << "enter secret: ";
            std::cin.getline(v->entries[i].value, 511);            
            v->entries[i].active = true;
            return true;
        }
    }
    std::cerr << "vault full\n";
    return false;
}

bool vault_delete(vault* v, const char* key) {
    for (size_t i = 0; i < v->max_entries; ++i) {
        if (v->entries[i].active) {
            if (!strcmp(v->entries[i].key, key)) {
                sodium_memzero(&v->entries[i], sizeof(v->entries[i]));
                return true;

            }
        }
    }
    return false;
}

const char* vault_get(vault* v, const char* key) {
    for (size_t i = 0; i < v->max_entries; ++i) {
        if (v->entries[i].active) {
            if (!strcmp(v->entries[i].key, key)) {
                return v->entries[i].value;
            }
        }
    }
    return nullptr;
}

void vault_destroy(vault* v) {
    secure_free(v->raw_memory, v->memory_size);
    v->raw_memory = nullptr;
    v->entries = nullptr;
    v->memory_size = 0;
    v->max_entries = 0;
}

bool vault_save(
    vault* v,
    const unsigned char* key,
    const unsigned char* salt,
    const char* path
) {
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ciphertext_len;
    std::vector<unsigned char> ciphertext(v->memory_size + crypto_aead_aes256gcm_ABYTES);
    crypto_aead_aes256gcm_encrypt(
        ciphertext.data(), 
        &ciphertext_len,
        reinterpret_cast<const unsigned char*>(v->entries), v->memory_size,
        nullptr, 
        0,
        nullptr,
        nonce, key
    );
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "failed to open file\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(salt), crypto_pwhash_SALTBYTES);
    file.write(reinterpret_cast<const char*>(nonce), crypto_aead_aes256gcm_NPUBBYTES);
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
    file.close();
    return true;
}

bool vault_open(vault* v, const char* password, const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "failed to open file\n";
        return false;
    }
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    unsigned char salt[crypto_pwhash_SALTBYTES];
    file.read(reinterpret_cast<char*>(salt), crypto_pwhash_SALTBYTES);
    unsigned char key[crypto_box_SEEDBYTES];
    if (crypto_pwhash(
        key, 
        crypto_box_SEEDBYTES, 
        password, 
        strlen(password), 
        salt, 
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
    ) < 0) {
        std::cout << "error deriving key" << "\n";
        return false;
    }
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    file.read(reinterpret_cast<char*>(nonce), crypto_aead_aes256gcm_NPUBBYTES);
    size_t encrypted_data_len = file_size - crypto_pwhash_SALTBYTES - crypto_aead_aes256gcm_NPUBBYTES;
    std::vector<unsigned char> ciphertext(encrypted_data_len);
    file.read(reinterpret_cast<char*>(ciphertext.data()), encrypted_data_len);

    unsigned long long decrypted_len;
    if (crypto_aead_aes256gcm_decrypt(
        reinterpret_cast<unsigned char*>(v->entries), &decrypted_len,
        nullptr,
        ciphertext.data(), encrypted_data_len,
        nullptr, 0,
        nonce, 
        key
    ) != 0) {
        std::cerr << "decryption failed - wrong password or tampered file\n";
        return false;
    }
    return true;
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