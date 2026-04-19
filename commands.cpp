#include <fstream>
#include <iostream>
#include <sodium.h>
#include "commands.h"
#include "crypto.h"
#include "log.h"
#include "memory.h"
#include "vault.h"

std::map<std::string, command> commands = {
    {"create",  {cmd_create,  "create a new vault", "muninn create -o <file>"}},
    {"add",     {cmd_add,     "add a secret to the vault", "muninn add -i <file>"}},
    {"get",     {cmd_get,     "retrieve a secret from the vault", "muninn get -i <file> -k <key>"}},
    {"delete",  {cmd_delete,  "delete a secret from the vault", "muninn delete -i <file>"}},
    {"list",    {cmd_list,    "list all secret from the vault", "muninn list -i <file>"}}
};

int cmd_create(int argc, char* argv[]) {
    if (argc < 4 || strcmp(argv[2], "-o") < 0) {
        LOG_ERROR("usage: " << commands[argv[1]].usage);
        return 1;
    }
    std::string path = std::string(argv[3]) + ".muninn";
    if (std::ifstream(path).good()) {
        LOG_ERROR("vault already exists: " << path);
        return 1;
    }

    unsigned char* secure_buf = static_cast<unsigned char*>(secure_alloc(4096));
    char* password = reinterpret_cast<char*>(secure_buf);
    unsigned char* key = secure_buf + 128;
    password_get(password, 127, "Password: ");

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    if (!key_derive(password, salt, key)) {
        secure_free(secure_buf, 4096);
        return 1;
    }

    vault v;
    if (!vault_init(&v, MAX_ENTRIES)) {
        return 1;
    }
    if (!vault_save(&v, key, salt, path.c_str())) {
        return 1;
    }

    LOG_INFO("successfully created vault " << path);
    vault_destroy(&v);
    secure_free(secure_buf, 4096);
    return 0;
}

int cmd_add(int argc, char* argv[]) {
    if (argc < 4 || strcmp(argv[2], "-i") < 0) {
        LOG_ERROR("usage: " << commands[argv[1]].usage);
        return 1;
    }
    std::string path = std::string(argv[3]) + ".muninn";
    unsigned char* secure_buf = static_cast<unsigned char*>(secure_alloc(4096));
    char* password = reinterpret_cast<char*>(secure_buf);
    vault v;

    if (!vault_start_session(&v, path.c_str(), password)) {
        secure_free(secure_buf, 4096);
        return 1;
    }

    vault_add(&v);
    vault_save(&v, v.key, v.salt, path.c_str());
    vault_destroy(&v);
    secure_free(secure_buf, 4096);
    return 0;
}
int cmd_get(int argc, char* argv[]) {
    if (argc < 6 || strcmp(argv[2], "-i") < 0 || strcmp(argv[4], "-k") < 0) {
        LOG_ERROR("usage: " << commands[argv[1]].usage);
        return 1;
    }
    std::string path = std::string(argv[3]) + ".muninn";
    unsigned char* secure_buf = static_cast<unsigned char*>(secure_alloc(4096));
    char* password = reinterpret_cast<char*>(secure_buf);
    vault v;
    if (!vault_start_session(&v, path.c_str(), password)) {
        secure_free(secure_buf, 4096);
        return 1;
    }
    if (!vault_get(&v, argv[5])) {
        vault_destroy(&v);
        secure_free(secure_buf, 4096);
        return 1;
    }
    vault_destroy(&v);
    secure_free(secure_buf, 4096);
    return 0;
}
int cmd_delete(int argc, char* argv[]) {
    return 0;
}
int cmd_list(int argc, char* argv[]) {
    return 0;
}