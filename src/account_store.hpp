// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <mutex>
#include <optional>
#include <string>

namespace pbsd {
// Device-managed encrypted session. Legacy passphrase vaults remain separate.
class AccountStore {
public:
  explicit AccountStore(std::string directory);
  bool saved() const;
  void save(const std::string &token);
  std::optional<std::string> restore() const;
  void forget();
private:
  std::string directory_;
  mutable std::mutex mutex_;
};
} // namespace pbsd
