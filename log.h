#pragma once
#include <iostream>

#define LOG_INFO(msg) std::cout << "[+] " << msg << "\n"
#define LOG_ERROR(msg) std::cerr << "[!] " << msg << "\n"
#define LOG_WARN(msg) std::cerr << "[*] " << msg << "\n"