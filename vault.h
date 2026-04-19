#pragma once
#include <unistd.h>
constexpr size_t MAX_ENTRIES = 64;

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
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_box_SEEDBYTES];
};

bool vault_init(vault *v, size_t max_entries);
void vault_debug(vault* v);
bool vault_add(vault* v);
bool vault_delete(vault* v, const char* key);
bool vault_get(vault* v, const char* key);
void vault_destroy(vault* v);
bool vault_save(
    vault* v,
    const unsigned char* key,
    const unsigned char* salt,
    const char* path
);
bool vault_open(
    vault* v, 
    const char* password, 
    const char* path
);
bool vault_start_session(vault* v, const char* path, char* password);