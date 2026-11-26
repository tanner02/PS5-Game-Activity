// SPDX-License-Identifier: GPL-3.0-or-later
#include "activity_settings.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pbsd {
namespace {
using Json = nlohmann::json;
constexpr std::size_t settings_limit = 4096;
const char *settings_name = "/activity-settings.json";

bool load_enabled(const std::string &path) {
  int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return false;
  struct Close { int fd; ~Close() { close(fd); } } closer{fd};
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      st.st_size > static_cast<off_t>(settings_limit))
    return false;
  std::string data(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t at = 0;
  while (at < data.size()) {
    ssize_t n = read(fd, data.data() + at, data.size() - at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    at += static_cast<std::size_t>(n);
  }
  char extra;
  ssize_t n;
  do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
  if (n != 0) return false;
  unsigned enabled_keys = 0;
  auto parsed = Json::parse(data, [&](int, Json::parse_event_t event, Json &value) {
    if (event == Json::parse_event_t::key && value == "enabled") ++enabled_keys;
    return true;
  }, false);
  return parsed.is_object() && parsed.size() == 1 && enabled_keys == 1 && parsed.contains("enabled") &&
      parsed["enabled"].is_boolean() && parsed["enabled"].get<bool>();
}
} // namespace

ActivitySettings::ActivitySettings(const std::string &directory)
    : directory_(directory) {
  enabled_ = load_enabled(directory_ + settings_name);
}

void ActivitySettings::set_enabled(bool enabled) {
  std::lock_guard lock(mutex_);
  if (enabled_.load() == enabled) return;
  if (mkdir(directory_.c_str(), 0700) < 0 && errno != EEXIST)
    throw std::runtime_error("Could not create activity settings directory");
  std::string pattern = directory_ + "/.activity-settings-XXXXXX";
  std::vector<char> path(pattern.begin(), pattern.end());
  path.push_back('\0');
  int fd = mkstemp(path.data());
  if (fd < 0) throw std::runtime_error("Could not stage activity settings");
  struct Temporary {
    int fd;
    const char *path;
    ~Temporary() {
      if (fd >= 0) close(fd);
      if (path) unlink(path);
    }
  } temporary{fd, path.data()};
  if (fchmod(fd, 0600) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    throw std::runtime_error("Could not secure activity settings");
  const std::string data = Json{{"enabled", enabled}}.dump() + "\n";
  std::size_t at = 0;
  while (at < data.size()) {
    const ssize_t n = write(fd, data.data() + at, data.size() - at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) throw std::runtime_error("Could not write activity settings");
    at += static_cast<std::size_t>(n);
  }
  if (fsync(fd) < 0)
    throw std::runtime_error("Could not flush activity settings");
  temporary.fd = -1;
  if (close(fd) < 0)
    throw std::runtime_error("Could not close activity settings");
  if (rename(path.data(), (directory_ + settings_name).c_str()) < 0)
    throw std::runtime_error("Could not save activity settings");
  temporary.path = nullptr;
  enabled_ = enabled;
}

std::string discord_game_image(const Json &response) {
  if (!response.is_array() || response.size() != 1 || !response[0].is_object()) return {};
  const auto path = response[0].find("external_asset_path");
  if (path == response[0].end() || !path->is_string()) return {};
  const auto &value = path->get_ref<const std::string &>();
  if (!value.starts_with("external/") || value.size() > 512 ||
      value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~/%?=&+") != value.npos ||
      value.find("/../") != value.npos || value.ends_with("/..")) return {};
  return "mp:" + value;
}

nlohmann::json game_activity_presence(bool enabled, const std::optional<GameTitle> &game,
                                      const std::string &image) {
  Json activities = Json::array();
  if (enabled && game) {
    Json activity{{"name", game->name}, {"type", 0}};
    if (!image.empty()) {
      activity["application_id"] = game_activity_application_id;
      activity["assets"] = {{"large_image", image}, {"large_text", game->name}};
    }
    activities.push_back(std::move(activity));
  }
  return {{"since", 0}, {"status", "online"},
          {"activities", std::move(activities)}, {"afk", false}};
}
} // namespace pbsd
