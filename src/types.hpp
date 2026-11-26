// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace pbsd {
using Bytes = std::vector<std::uint8_t>;
using View = std::span<const std::uint8_t>;
std::uint64_t monotonic_ms();
void secure_erase(void *data, std::size_t size);
} // namespace pbsd
