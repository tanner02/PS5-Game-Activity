// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "account_store.hpp"
#include "game_artwork.hpp"
#include "login_verification.hpp"
#include <atomic>

namespace pbsd {
class ActivitySession {
public:
  explicit ActivitySession(const std::string &directory);
  ~ActivitySession();
  Json status();
  void sign_in();
  void verify(const Json &body);
  void sign_out();
  void cancel();

private:
  void launch(bool linking);
  void stop();
  void qr_login();
  void gateway();
  void set_state(std::string state, std::string error = {});
  AccountStore account_store_;
  GameArtwork game_artwork_;
  LoginVerification verification_;
  std::mutex mutex_;
  std::atomic<bool> stopping_{false};
  std::thread worker_;
  std::string state_, error_, username_, qr_url_, token_;
  std::optional<GameTitle> activity_game_;
};
}
