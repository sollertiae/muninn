#include <fstream>
#include <iostream>
#include <sodium.h>
#include "memory.h"
#include "vault.h"

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

bool vault_open(
    vault* v, 
    const char* password, 
    const char* path
) {
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