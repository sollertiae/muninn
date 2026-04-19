#pragma once
#include <unistd.h>


constexpr size_t SECURE_BUF_SIZE = 4096;
bool key_derive(const char* password, const unsigned char* salt, unsigned char* key);
void password_get(char* buf, size_t len, const char* prompt);