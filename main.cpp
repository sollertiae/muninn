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

struct secretEntry {
    char key[128];
    char value[512];
};

struct Vault {
    secretEntry* entries;
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
    std::cout << "memory is now read-only\n";   
}

void secure_free(void* ptr, size_t size) {
    std::cout << "Freeing memory" << ptr << " " << size << "\n";
    secure_unseal(ptr, size);
    std::cout << "before: " << static_cast<char*>(ptr) << "\n";
    sodium_memzero(ptr, size);
    std::cout << "after: " << static_cast<char*>(ptr) << "\n";
    munmap(ptr, size);
}

bool vault_init(Vault *vault, size_t max_entries) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return false;
    }
    size_t size = sizeof(secretEntry) * max_entries;
    void* ptr = secure_alloc(size);
    if (!ptr) {
        std::cerr << "allocation failed\n";
        return false;
    }
    sodium_memzero(ptr, size);
    vault->entries = static_cast<secretEntry*>(ptr);
    vault->raw_memory = ptr;
    vault->memory_size = size;
    vault->max_entries = max_entries;
    return true;
}

int main() {
    
    const size_t MAX_ENTRIES = 64;
    signal(SIGBUS, handle_sigbus);
    
    Vault vault;
    if (!vault_init(&vault, MAX_ENTRIES)) {
        return 1;
    }
    std::cout << "enter key: ";
    std::cin.getline(vault.entries[0].key, 127);
    std::cout << "enter secret: ";
    std::cin.getline(vault.entries[0].value, 511);
    std::cout << "key: " << vault.entries[0].key << "\n";
    std::cout << "value: " << vault.entries[0].value << "\n";

    secure_seal(vault.raw_memory, vault.memory_size);

    secure_free(vault.raw_memory, vault.memory_size);
    return 0;
}