#include <iostream>
#include <sys/mman.h>
#include <sodium.h>
#include "memory.h"
#include "log.h"

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
        LOG_ERROR("mlock failed");
        munmap(ptr, size);
        return nullptr;
    }
    return ptr;
}

void secure_seal(void* ptr, size_t size) {
    if (mprotect(ptr, size, PROT_READ) < 0) {
        LOG_ERROR("mprotect failed");
    }
}

void secure_unseal(void* ptr, size_t size) {
    if (mprotect(ptr, size, PROT_READ | PROT_WRITE) < 0) {
        LOG_ERROR("mprotect failed");
    }
}

void secure_free(void* ptr, size_t size) {
    secure_unseal(ptr, size);
    sodium_memzero(ptr, size);
    munmap(ptr, size);
}