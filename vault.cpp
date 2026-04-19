#include <fstream>
#include <iostream>
#include <sodium.h>
#include "crypto.h"
#include "memory.h"
#include "log.h"
#include "vault.h"

bool vault_init(vault *v, size_t max_entries) {
    if (sodium_init() < 0) {
        LOG_ERROR("libsodium init failed");
        return false;
    }
    size_t size = sizeof(secret_entry) * max_entries;
    void* ptr = secure_alloc(size);
    if (!ptr) {
        LOG_ERROR("allocation failed");
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
            LOG_INFO("slot " << i << ": " << v->entries[i].key << " -> " << v->entries[i].value);
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
        LOG_ERROR("failed to open file");
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
        LOG_ERROR("failed to open file");
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    file.read(reinterpret_cast<char*>(v->salt), crypto_pwhash_SALTBYTES);

    if (crypto_pwhash(
        v->key, 
        crypto_box_SEEDBYTES, 
        password, 
        strlen(password), 
        v->salt, 
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
    ) < 0) {
        LOG_ERROR("error deriving key");
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
        v->key
    ) != 0) {
        LOG_ERROR("decryption failed - wrong password or tampered file");
        return false;
    }
    return true;
}

bool vault_get(vault* v, const char* key) {
    for (size_t i = 0; i < v->max_entries; ++i) {
        if (v->entries[i].active) {
            if (!strcmp(v->entries[i].key, key)) {
                FILE* pipe = popen("pbcopy", "w");
                if (pipe) {
                    fwrite(v->entries[i].value, 1, strlen(v->entries[i].value), pipe);
                    pclose(pipe);
                    LOG_INFO("key copied to clipboard");
                    return true;
                }
            }
        }
    }
    LOG_ERROR("key not found: " << key);
    return false;
}

bool vault_start_session(vault* v, const char* path, char* password) {
    password_get(password, 127, "Password: ");

    if (!vault_init(v, MAX_ENTRIES))
        return false;
    if (!vault_open(v, password, path)) {
        LOG_ERROR("failed to open vault: " << path);
        vault_destroy(v);
        return false;
    }
    return true;
}