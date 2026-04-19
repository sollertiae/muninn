#pragma once
#include <unistd.h>

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

bool vault_init(vault *v, size_t max_entries);
void vault_debug(vault* v);
bool vault_add(vault* v);
bool vault_delete(vault* v, const char* key);
const char* vault_get(vault* v, const char* key);
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
