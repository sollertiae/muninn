#pragma once
#include <functional>
#include <map>

using command_fn = std::function<int(int argc, char* argv[])>;
struct command {
    command_fn fn;
    std::string desc;
    std::string usage;
};

extern std::map<std::string, command> commands;

int cmd_create(int argc, char* argv[]);
int cmd_add(int argc, char* argv[]);
int cmd_get(int argc, char* argv[]);
int cmd_delete(int argc, char* argv[]);
int cmd_list(int argc, char* argv[]);
int cmd_help(int argc, char* argv[]);