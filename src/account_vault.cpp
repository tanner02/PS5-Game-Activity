// SPDX-License-Identifier: GPL-3.0-or-later
#include "account_vault.hpp"
#include "net.hpp"
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace pbsd {
using Json = nlohmann::json;
static void require(bool ok, const char *message) {
  if (!ok) throw std::runtime_error(message);
}
static Bytes vault_key(const std::string &pass, View salt) {
  require(pass.size() >= 10 && pass.size() <= 1024,
          "Use an unlock passphrase of 10 to 1024 characters");
  Bytes key(32);
  require(EVP_PBE_scrypt(pass.data(), pass.size(), salt.data(), salt.size(),
                         32768, 8, 1, 64 * 1024 * 1024, key.data(),
                         key.size()) == 1,
          "Vault key derivation failed");
  return key;
}
void save_vault(const std::string &path, const std::string &pass,
                const std::string &token) {
  require(token.size() >= 20 && token.size() <= 4096,
          "Invalid account session");
  auto salt = random_bytes(16), nonce = random_bytes(12),
       key = vault_key(pass, salt);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  require(ctx != nullptr, "Vault cipher unavailable");
  Bytes out(token.size() + 16), tag(16);
  int n = 0, m = 0;
  bool ok =
      EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(),
                         nonce.data()) == 1 &&
      EVP_EncryptUpdate(ctx, out.data(), &n,
                        reinterpret_cast<const unsigned char *>(token.data()),
                        static_cast<int>(token.size())) == 1 &&
      EVP_EncryptFinal_ex(ctx, out.data() + n, &m) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  secure_erase(key.data(), key.size());
  require(ok, "Vault encryption failed");
  out.resize(n + m);
  Json j{{"v", 1},
         {"salt", base64(salt)},
         {"nonce", base64(nonce)},
         {"tag", base64(tag)},
         {"data", base64(out)}};
  auto temp = path + ".tmp";
  int fd = ::open(temp.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  require(fd >= 0, "Cannot save account vault");
  if (fchmod(fd, 0600)) {
    ::close(fd);
    std::remove(temp.c_str());
    throw std::runtime_error("Cannot protect account vault");
  }
  auto data = j.dump();
  std::size_t at = 0;
  while (at < data.size()) {
    auto rc = ::write(fd, data.data() + at, data.size() - at);
    if (rc <= 0) {
      ::close(fd);
      std::remove(temp.c_str());
      throw std::runtime_error("Vault write failed");
    }
    at += rc;
  }
  bool saved = fsync(fd) == 0;
  ::close(fd);
  require(saved && std::rename(temp.c_str(), path.c_str()) == 0,
          "Vault commit failed");
}
std::string load_vault(const std::string &path, const std::string &pass) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  require(fd >= 0, "No saved account");
  struct Close { int fd; ~Close() { ::close(fd); } } closer{fd};
  struct stat st{};
  require(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= 16384,
          "Invalid account vault");
  std::string raw(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t at = 0;
  while (at < raw.size()) {
    const auto n = ::read(fd, raw.data() + at, raw.size() - at);
    if (n < 0 && errno == EINTR) continue;
    require(n > 0, "Could not read saved account");
    at += static_cast<std::size_t>(n);
  }
  auto j = Json::parse(raw);
  require(j.at("v") == 1, "Unsupported account vault");
  auto salt = unbase64(j.at("salt")), nonce = unbase64(j.at("nonce")),
       tag = unbase64(j.at("tag")), cipher = unbase64(j.at("data"));
  require(salt.size() == 16 && nonce.size() == 12 && tag.size() == 16 &&
              cipher.size() >= 20 && cipher.size() <= 4096,
          "Invalid account vault");
  auto key = vault_key(pass, salt);
  Bytes plain(cipher.size() + 16);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  require(ctx != nullptr, "Vault cipher unavailable");
  int n = 0, m = 0;
  bool ok =
      EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(),
                         nonce.data()) == 1 &&
      EVP_DecryptUpdate(ctx, plain.data(), &n, cipher.data(), cipher.size()) ==
          1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) == 1 &&
      EVP_DecryptFinal_ex(ctx, plain.data() + n, &m) == 1;
  EVP_CIPHER_CTX_free(ctx);
  secure_erase(key.data(), key.size());
  if (!ok) {
    secure_erase(plain.data(), plain.size());
    throw std::runtime_error("Incorrect passphrase or damaged vault");
  }
  std::string token(reinterpret_cast<const char *>(plain.data()), n + m);
  secure_erase(plain.data(), plain.size());
  return token;
}
} // namespace pbsd
