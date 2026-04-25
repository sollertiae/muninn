#include <cstring>
#include <iostream>
#include <sodium.h>
#include <termios.h>
#include "crypto.h"
#include "log.h"

constexpr int MUNINN_KDF_ALG = crypto_pwhash_ALG_ARGON2ID13;
constexpr size_t MUNINN_KDF_OPSLIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE;
constexpr size_t MUNINN_KDF_MEMLIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE;
constexpr size_t MUNINN_KEY_SIZE = crypto_box_SEEDBYTES;

bool key_derive(const char* password, const unsigned char* salt, unsigned char* key) {
    if (crypto_pwhash(
        key, 
        MUNINN_KEY_SIZE, 
        password, 
        strlen(password), 
        salt, 
        MUNINN_KDF_OPSLIMIT,
        MUNINN_KDF_MEMLIMIT,
        MUNINN_KDF_ALG
    ) < 0) {
        LOG_ERROR("error deriving key");
        return false;
    }
    return true;
}

void password_get(char* buf, size_t len, const char* prompt) {
    std::cout << prompt << "\n";
    termios old_t, new_t;
    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    std::cin.getline(buf, len);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    std::cout << "\n";
}