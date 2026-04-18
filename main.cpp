#include <iostream>
#include <sys/mman.h>
#include <csignal>
#include <unistd.h>
#include <sodium.h>
#include <strings.h>

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
    secure_unseal(v->raw_memory, v->memory_size);
    secure_free(v->raw_memory, v->memory_size);
    munmap(v->raw_memory, v->memory_size);
    v->raw_memory = nullptr;
    v->entries = nullptr;
    v->memory_size = 0;
    v->max_entries = 0;
}

int main() {
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
        return 1;
    }
    vault_add(&v);
    vault_debug(&v);
    vault_get(&v, "github");
    vault_delete(&v, "github");
    vault_debug(&v);
    vault_destroy(&v);
    vault_debug(&v);
    return 0;
}