#pragma once
#include <Windows.h>
#include <string>
#include <cstdio>
#include "Utility.h"

class ShellCmd {
public:
	bool Run(const char *in, std::string &out);
	bool Cmd(const char *in, std::string &out);
	bool Powershell(const char *in, std::string &out);
};