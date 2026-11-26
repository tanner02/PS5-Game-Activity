// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace pbsd {
using Json = nlohmann::json;

// Holds a single challenge for completion by the user. Never solves a challenge.
class LoginVerification {
public:
  ~LoginVerification();
  void issue(const Json &response, std::uint64_t deadline_ms);
  Json status(std::uint64_t now_ms) const;
  void submit(const std::string &challenge_id, const std::string &solution,
              std::uint64_t now_ms);
  std::optional<std::map<std::string, std::string>> take(std::uint64_t now_ms);
  void clear();

private:
  void clear_locked();
  mutable std::mutex mutex_;
  std::string id_, sitekey_, rqdata_, rqtoken_, session_id_, solution_;
  std::uint64_t deadline_ms_{};
  bool submitted_{};
};
} // namespace pbsd
