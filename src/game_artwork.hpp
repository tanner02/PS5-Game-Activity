// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "game_activity.hpp"
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

namespace pbsd {
bool public_game_image_url(std::string_view url);
std::string game_store_url(const GameTitle &game);
std::string parse_game_store_image(std::string_view page, const GameTitle &game);

// Never performs network I/O on the caller's gateway/media thread. Both hits
// and misses are cached; only the latest waiting title needs to be fetched.
class GameArtwork {
public:
  using Fetch = std::function<std::string(const std::string &)>;
  explicit GameArtwork(Fetch fetch = {}, const std::string &cache_path = {});
  ~GameArtwork();
  std::string image(const GameTitle &game);
private:
  struct Entry { std::string image; std::uint64_t expires; };
  Fetch fetch_;
  std::mutex mutex_;
  std::condition_variable changed_;
  std::map<std::string, Entry> cache_;
  std::optional<GameTitle> pending_;
  std::string active_;
  bool stopping_{};
  std::thread worker_;
  void run();
};
} // namespace pbsd
