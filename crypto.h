#pragma once
#include <unistd.h>

bool key_derive(const char* password, const unsigned char* salt, unsigned char* key);
void password_get(char* buf, size_t len, const char* prompt);