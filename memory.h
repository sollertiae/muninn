#pragma once
#include <unistd.h>

void* secure_alloc(size_t size);
void secure_seal(void* ptr, size_t size);
void secure_unseal(void* ptr, size_t size);
void secure_free(void* ptr, size_t size);