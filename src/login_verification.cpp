// SPDX-License-Identifier: GPL-3.0-or-later
#include "login_verification.hpp"
#include "net.hpp"
#include <algorithm>
#include <stdexcept>

namespace pbsd {
namespace {
bool has_controls(const std::string &value) {
  return std::any_of(value.begin(), value.end(), [](unsigned char c) {
    return c < 0x20 || c == 0x7f;
  });
}

// Validate in place before copying server values into owned state.
const std::string &field(const Json &response, const char *name,
                         std::size_t limit, bool header = false) {
  static const std::string empty;
  const auto it = response.find(name);
  if (it == response.end() || it->is_null())
    return empty;
  if (!it->is_string())
    throw std::runtime_error("Invalid login verification field type");
  const auto &value = it->get_ref<const std::string &>();
  if (value.size() > limit || (header && has_controls(value)))
    throw std::runtime_error("Invalid login verification field");
  return value;
}

void erase(std::string &value) {
  if (!value.empty())
    secure_erase(value.data(), value.size());
  value.clear();
}
} // namespace

LoginVerification::~LoginVerification() { clear(); }

void LoginVerification::issue(const Json &response, std::uint64_t deadline_ms) {
  std::lock_guard lock(mutex_);
  clear_locked();
  if (!response.is_object() ||
      field(response, "captcha_service", 128) != "hcaptcha")
    throw std::runtime_error("Unsupported login verification service");
  const auto &sitekey = field(response, "captcha_sitekey", 128);
  if (sitekey.empty() ||
      !std::all_of(sitekey.begin(), sitekey.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '-';
      }))
    throw std::runtime_error("Invalid login verification sitekey");
  const auto &rqdata = field(response, "captcha_rqdata", 8192);
  const auto &rqtoken = field(response, "captcha_rqtoken", 4096, true);
  const auto &session = field(response, "captcha_session_id", 512, true);
  try {
    sitekey_ = sitekey;
    rqdata_ = rqdata;
    rqtoken_ = rqtoken;
    session_id_ = session;
    deadline_ms_ = deadline_ms;
    id_ = random_hex(16);
  } catch (...) {
    clear_locked();
    throw;
  }
}

Json LoginVerification::status(std::uint64_t now_ms) const {
  std::lock_guard lock(mutex_);
  if (id_.empty() || submitted_ || now_ms >= deadline_ms_)
    return nullptr;
  return {{"id", id_}, {"service", "hcaptcha"}, {"sitekey", sitekey_},
          {"rqdata", rqdata_}};
}

void LoginVerification::submit(const std::string &challenge_id,
                               const std::string &solution,
                               std::uint64_t now_ms) {
  std::lock_guard lock(mutex_);
  if (now_ms >= deadline_ms_)
    clear_locked();
  if (id_.empty() || submitted_ || challenge_id != id_)
    throw std::runtime_error("Login verification is no longer active");
  if (solution.empty() || solution.size() > 8192 || has_controls(solution))
    throw std::runtime_error("Invalid login verification solution");
  solution_ = solution;
  submitted_ = true;
}

std::optional<std::map<std::string, std::string>>
LoginVerification::take(std::uint64_t now_ms) {
  std::lock_guard lock(mutex_);
  if (now_ms >= deadline_ms_) {
    clear_locked();
    return std::nullopt;
  }
  if (id_.empty() || !submitted_)
    return std::nullopt;
  std::map<std::string, std::string> headers{{"X-Captcha-Key", solution_}};
  if (!rqtoken_.empty())
    headers.emplace("X-Captcha-Rqtoken", rqtoken_);
  if (!session_id_.empty())
    headers.emplace("X-Captcha-Session-Id", session_id_);
  clear_locked();
  return headers;
}

void LoginVerification::clear_locked() {
  for (auto *value : {&id_, &sitekey_, &rqdata_, &rqtoken_, &session_id_, &solution_})
    erase(*value);
  deadline_ms_ = 0;
  submitted_ = false;
}

void LoginVerification::clear() {
  std::lock_guard lock(mutex_);
  clear_locked();
}
} // namespace pbsd
