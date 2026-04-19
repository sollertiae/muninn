#include <iostream>
#include <sys/mman.h>
#include <sodium.h>
#include "memory.h"

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