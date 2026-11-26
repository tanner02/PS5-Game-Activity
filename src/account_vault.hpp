// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
namespace pbsd {
void save_vault(const std::string &path, const std::string &passphrase,
                const std::string &token);
std::string load_vault(const std::string &path, const std::string &passphrase);
}
