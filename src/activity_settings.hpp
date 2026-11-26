// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "game_activity.hpp"
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>

namespace pbsd {
class ActivitySettings {
public:
  explicit ActivitySettings(const std::string &directory);
  bool enabled() const { return enabled_.load(); }
  void set_enabled(bool enabled);

private:
  std::string directory_;
  std::atomic<bool> enabled_{false};
  std::mutex mutex_;
};
// Application namespace used by the PS5 playing activity integration.
inline constexpr char game_activity_application_id[] = "1565829739241807882";
std::string discord_game_image(const nlohmann::json &response);
nlohmann::json game_activity_presence(bool enabled, const std::optional<GameTitle> &game,
                                      const std::string &image = {});
} // namespace pbsd
