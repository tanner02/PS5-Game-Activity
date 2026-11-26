// SPDX-License-Identifier: GPL-3.0-or-later
#include "account_store.hpp"
#include "account_vault.hpp"
#include "net.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pbsd {
namespace {
bool exists(const std::string &path) {
  struct stat st{};
  return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}
struct Secret {
  std::string value;
  ~Secret() { secure_erase(value.data(), value.size()); }
};
std::string read_key(const std::string &path) {
  int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) throw std::runtime_error("Saved account key is missing; link the account again");
  struct Close { int fd; ~Close() { close(fd); } } closer{fd};
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != 64 || (st.st_mode & 077))
    throw std::runtime_error("Saved account key is invalid; link the account again");
  Secret key{std::string(64, '\0')};
  std::size_t at = 0;
  while (at < key.value.size()) {
    const auto n = read(fd, key.value.data() + at, key.value.size() - at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) throw std::runtime_error("Could not read saved account key");
    at += static_cast<std::size_t>(n);
  }
  if (key.value.find_first_not_of("0123456789abcdef") != std::string::npos)
    throw std::runtime_error("Saved account key is invalid; link the account again");
  return key.value;
}
void write_key(const std::string &path, const std::string &key) {
  std::string pattern = path + ".XXXXXX";
  std::vector<char> name(pattern.begin(), pattern.end()); name.push_back('\0');
  const int fd = mkstemp(name.data());
  if (fd < 0) throw std::runtime_error("Could not create saved account key");
  struct Temporary {
    int fd; const char *path;
    ~Temporary() { if (fd >= 0) close(fd); if (path) unlink(path); }
  } file{fd, name.data()};
  if (fchmod(fd, 0600) || fcntl(fd, F_SETFD, FD_CLOEXEC))
    throw std::runtime_error("Could not protect saved account key");
  std::size_t at = 0;
  while (at < key.size()) {
    const auto n = write(fd, key.data() + at, key.size() - at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) throw std::runtime_error("Could not save account key");
    at += static_cast<std::size_t>(n);
  }
  if (fsync(fd)) throw std::runtime_error("Could not flush account key");
  const int rc = close(fd); file.fd = -1;
  if (rc || rename(name.data(), path.c_str()))
    throw std::runtime_error("Could not commit saved account key");
  file.path = nullptr;
}
} // namespace
AccountStore::AccountStore(std::string directory) : directory_(std::move(directory)) {}
bool AccountStore::saved() const {
  std::lock_guard lock(mutex_);
  return exists(directory_ + "/account-auto.vault");
}
void AccountStore::save(const std::string &token) {
  std::lock_guard lock(mutex_);
  if (mkdir(directory_.c_str(), 0700) < 0 && errno != EEXIST)
    throw std::runtime_error("Could not create account directory");
  const int directory_fd = open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd < 0) throw std::runtime_error("Could not open account directory");
  const int protected_directory = fchmod(directory_fd, 0700);
  close(directory_fd);
  if (protected_directory) throw std::runtime_error("Could not protect account directory");
  const auto key_path = directory_ + "/account-auto.key";
  Secret key;
  struct stat st{};
  if (lstat(key_path.c_str(), &st) == 0) key.value = read_key(key_path);
  else {
    if (errno != ENOENT) throw std::runtime_error("Could not inspect saved account key");
    // Never replace a missing key under an existing vault silently.
    if (exists(directory_ + "/account-auto.vault"))
      throw std::runtime_error("Saved account key is missing; forget this saved account and link again");
    key.value = random_hex(32);
    write_key(key_path, key.value);
  }
  const auto vault_path = directory_ + "/account-auto.vault";
  if (exists(vault_path)) {
    // Detect a mismatched key before replacing a previously saved session.
    Secret previous{load_vault(vault_path, key.value)};
  }
  save_vault(vault_path, key.value, token);
}
std::optional<std::string> AccountStore::restore() const {
  std::lock_guard lock(mutex_);
  if (!exists(directory_ + "/account-auto.vault")) return std::nullopt;
  Secret key{read_key(directory_ + "/account-auto.key")};
  return load_vault(directory_ + "/account-auto.vault", key.value);
}
void AccountStore::forget() {
  std::lock_guard lock(mutex_);
  for (const auto *name : {"/account-auto.vault", "/account-auto.vault.tmp", "/account-auto.key"}) {
    if (unlink((directory_ + name).c_str()) && errno != ENOENT)
      throw std::runtime_error("Could not remove saved account");
  }
}
} // namespace pbsd
