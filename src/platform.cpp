// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform.hpp"
#ifdef PBS_PS5
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <openssl/rand.h>
#include <sodium.h>
#include <stdexcept>
extern "C" int sceRandomGetRandomNumber(std::uint8_t *, std::size_t);
namespace {
int bytes(unsigned char *out, int size) {
  if (size < 0)
    return 0;
  while (size) {
    int count = std::min(size, 64);
    if (sceRandomGetRandomNumber(out, count) != 0)
      return 0;
    out += count;
    size -= count;
  }
  return 1;
}
int seed(const void *, int) { return 1; }
int add(const void *, int, double) { return 1; }
int status() { return 1; }
void cleanup() {}
const char *name() { return "ps5-sce-random"; }
std::uint32_t random32() {
  std::uint32_t value;
  if (!bytes(reinterpret_cast<unsigned char *>(&value), sizeof value))
    std::abort();
  return value;
}
void random_buffer(void *out, std::size_t count) {
  auto *p = static_cast<unsigned char *>(out);
  while (count) {
    int n = static_cast<int>(std::min<std::size_t>(count, 64));
    if (!bytes(p, n))
      std::abort();
    p += n;
    count -= n;
  }
}
void stir() {}
int close_random() { return 0; }
std::uint32_t uniform(std::uint32_t bound) {
  if (bound < 2)
    return 0;
  const std::uint32_t minimum = std::uint32_t(-bound) % bound;
  std::uint32_t value;
  do {
    value = random32();
  } while (value < minimum);
  return value % bound;
}
RAND_METHOD method{seed, bytes, cleanup, add, bytes, status};
randombytes_implementation sodium_random{name,    random32,      stir,
                                         uniform, random_buffer, close_random};
} // namespace
#endif
namespace pbsd {
void initialize_platform_random() {
#ifdef PBS_PS5
  unsigned char probe[16];
  if (!bytes(probe, sizeof probe))
    throw std::runtime_error("Console cryptographic random source unavailable");
  std::memset(probe, 0, sizeof probe);
  // The native SceRandom CSPRNG replaces filesystem/FreeBSD entropy interfaces
  // unavailable in payload processes. Encryption algorithms remain upstream.
  if (RAND_set_rand_method(&method) != 1 ||
      randombytes_set_implementation(&sodium_random) != 0)
    throw std::runtime_error("Console random-source registration failed");
#endif
}
} // namespace pbsd
