#include <iostream>
#include <sys/mman.h>
#include <csignal>
#include <unistd.h>
#include <sodium.h>
#include <strings.h>

void handle_sigbus(int sig) {
    write(STDOUT_FILENO, "write attempt\n", 29);
    _exit(1);
}
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

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }
    size_t size = 4096;
    signal(SIGBUS, handle_sigbus);
    void* ptr = secure_alloc(size);
    if (!ptr) {
        std::cerr << "allocation failed\n";
        return 1;
    }
    char* buf = static_cast<char*>(ptr);
    strcpy(buf, "secret data");
    std::cout << "wrote: " << buf << "\n";

    secure_seal(ptr, size);

    secure_free(ptr, size);
    return 0;
}