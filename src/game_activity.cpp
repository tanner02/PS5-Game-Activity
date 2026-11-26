// SPDX-License-Identifier: GPL-3.0-or-later
#include "game_activity.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <iterator>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifdef PBS_PS5
extern "C" int sceSystemServiceGetAppIdOfRunningBigApp(void);
extern "C" int sceLncUtilGetAppTitleId(std::uint32_t app_id, char *title_id);
#endif

namespace pbsd {
namespace {
using Json = nlohmann::json;
constexpr std::size_t metadata_limit = 1024 * 1024;

std::optional<std::string> read_file(const std::string &path) {
  const int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return std::nullopt;
  struct Close { int fd; ~Close() { close(fd); } } closer{fd};
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      static_cast<std::uint64_t>(st.st_size) > metadata_limit)
    return std::nullopt;
  std::string data(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t at = 0;
  while (at < data.size()) {
    const auto count = read(fd, data.data() + at, data.size() - at);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return std::nullopt;
    at += static_cast<std::size_t>(count);
  }
  char extra;
  ssize_t count;
  do { count = read(fd, &extra, 1); } while (count < 0 && errno == EINTR);
  if (count != 0) return std::nullopt;
  return data;
}

// Validate the complete UTF-8 string, then truncate at 128 codepoints. Never
// publish malformed text or hide a control character beyond the output bound.
std::optional<std::string> display_name(std::string_view text) {
  if (text.empty()) return std::nullopt;
  std::size_t count = 0, kept = 0;
  bool visible = false;
  for (std::size_t at = 0; at < text.size();) {
    const auto first = static_cast<unsigned char>(text[at++]);
    std::uint32_t codepoint;
    unsigned continuation;
    if (first < 0x80) { codepoint = first; continuation = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { codepoint = first & 31; continuation = 1; }
    else if (first >= 0xe0 && first <= 0xef) { codepoint = first & 15; continuation = 2; }
    else if (first >= 0xf0 && first <= 0xf4) { codepoint = first & 7; continuation = 3; }
    else return std::nullopt;
    if (continuation > text.size() - at) return std::nullopt;
    for (unsigned i = 0; i < continuation; ++i) {
      const auto byte = static_cast<unsigned char>(text[at++]);
      if ((byte & 0xc0) != 0x80) return std::nullopt;
      codepoint = (codepoint << 6) | (byte & 63);
    }
    if ((continuation == 1 && codepoint < 0x80) ||
        (continuation == 2 && codepoint < 0x800) ||
        (continuation == 3 && codepoint < 0x10000) ||
        codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
        codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f))
      return std::nullopt;
    if (++count <= 128) {
      kept = at;
      if (codepoint != ' ') visible = true;
    }
  }
  if (!visible) return std::nullopt;
  return std::string(text.substr(0, kept));
}

bool ascii_digits(std::string_view text) {
  return std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; });
}
bool valid_content_id(std::string_view value, std::string_view title_id) {
  return value.size() == 36 && value[0] >= 'A' && value[0] <= 'Z' &&
      value[1] >= 'A' && value[1] <= 'Z' && ascii_digits(value.substr(2, 4)) &&
      value[6] == '-' && value.substr(7, 9) == title_id && value[16] == '_' &&
      ascii_digits(value.substr(17, 2)) && value[19] == '-' &&
      std::all_of(value.begin() + 20, value.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_';
      });
}
void json_identifiers(const Json &root, GameTitle &title) {
  const auto content = root.find("contentId");
  if (content != root.end() && content->is_string()) {
    const auto &value = content->get_ref<const std::string &>();
    if (valid_content_id(value, title.title_id)) title.content_id = value;
  }
  const auto concept_field = root.find("conceptId");
  if (concept_field != root.end() && concept_field->is_string()) {
    const auto &value = concept_field->get_ref<const std::string &>();
    if (!value.empty() && value.size() <= 12 && ascii_digits(value)) title.concept_id = value;
  }
}

std::optional<GameTitle> json_title(const std::string &data,
                                     const std::string &title_id,
                                     const std::string &locale) {
  const auto root = Json::parse(data, nullptr, false);
  if (!root.is_object() || !root.contains("titleId") ||
      !root["titleId"].is_string() || root["titleId"] != title_id ||
      !root.contains("localizedParameters") || !root["localizedParameters"].is_object())
    return std::nullopt;
  const auto &localized = root["localizedParameters"];
  std::vector<std::string> languages{locale};
  const auto default_language = localized.find("defaultLanguage");
  if (default_language != localized.end() && default_language->is_string())
    languages.push_back(default_language->get<std::string>());
  languages.emplace_back("en-US");
  for (const auto &language : languages) {
    const auto entry = localized.find(language);
    if (entry == localized.end() || !entry->is_object()) continue;
    const auto name = entry->find("titleName");
    if (name != entry->end() && name->is_string())
      if (auto value = display_name(name->get_ref<const std::string &>())) {
        GameTitle title{title_id, std::move(*value)};
        json_identifiers(root, title);
        return title;
      }
  }
  return std::nullopt;
}

std::uint32_t le32(std::string_view data, std::size_t at) {
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i)
    value |= std::uint32_t(static_cast<unsigned char>(data[at + i])) << (8 * i);
  return value;
}
std::optional<GameTitle> sfo_title(std::string_view data, const std::string &title_id) {
  if (data.size() < 20 || data.substr(0, 4) != std::string_view("\0PSF", 4))
    return std::nullopt;
  const std::size_t keys = le32(data, 8), values = le32(data, 12), count = le32(data, 16);
  if (count > (data.size() - 20) / 16 || keys < 20 + count * 16 ||
      keys >= values || values >= data.size()) return std::nullopt;
  std::optional<std::string> id, name;
  std::string content_id;
  bool content_seen = false;
  for (std::size_t i = 0; i < count; ++i) {
    const auto at = 20 + i * 16;
    const std::size_t key = static_cast<unsigned char>(data[at]) |
        (std::size_t(static_cast<unsigned char>(data[at + 1])) << 8);
    const std::size_t length = le32(data, at + 4), capacity = le32(data, at + 8),
                      value = le32(data, at + 12);
    if (key >= values - keys || value > data.size() - values ||
        length > capacity || capacity > data.size() - values - value)
      return std::nullopt;
    const auto key_data = data.substr(keys + key, values - keys - key);
    const auto key_end = key_data.find('\0');
    if (key_end == std::string_view::npos) return std::nullopt;
    const auto field = key_data.substr(0, key_end);
    if (field == "CONTENT_ID") {
      const bool duplicate = content_seen;
      content_seen = true;
      content_id.clear();
      // Optional artwork identifiers must not invalidate an otherwise valid
      // title when their type, string encoding, or value is unsupported.
      if (!duplicate && static_cast<unsigned char>(data[at + 2]) == 4 &&
          static_cast<unsigned char>(data[at + 3]) == 2 && length) {
        const auto text = data.substr(values + value, length);
        if (text.back() == '\0' && text.find('\0') == length - 1 &&
            valid_content_id(text.substr(0, length - 1), title_id))
          content_id = text.substr(0, length - 1);
      }
      continue;
    }
    if (field != "TITLE_ID" && field != "TITLE") continue;
    // PSF UTF-8 strings use format 0x0204 and include their terminating NUL.
    if (static_cast<unsigned char>(data[at + 2]) != 4 ||
        static_cast<unsigned char>(data[at + 3]) != 2 || !length)
      return std::nullopt;
    const auto text = data.substr(values + value, length);
    if (text.back() != '\0' || text.find('\0') != length - 1)
      return std::nullopt;
    if (field == "TITLE_ID") {
      if (id) return std::nullopt;
      id = std::string(text.substr(0, length - 1));
    } else {
      if (name) return std::nullopt;
      name = display_name(text.substr(0, length - 1));
      if (!name) return std::nullopt;
    }
  }
  if (!id || *id != title_id || !name) return std::nullopt;
  GameTitle title{title_id, std::move(*name)};
  title.content_id = std::move(content_id);
  return title;
}
} // namespace

bool is_game_title_id(std::string_view id) {
  return id.size() == 9 && (id.substr(0, 4) == "PPSA" || id.substr(0, 4) == "CUSA") &&
      std::all_of(id.begin() + 4, id.end(), [](char c) { return c >= '0' && c <= '9'; });
}

bool is_game_content_id(std::string_view content_id, std::string_view title_id) {
  return is_game_title_id(title_id) && valid_content_id(content_id, title_id);
}

std::optional<GameTitle> read_game_metadata(const std::string &appmeta_root,
                                          const std::string &title_id,
                                          const std::string &locale) {
  if (!is_game_title_id(title_id)) return std::nullopt;
  const auto directory = appmeta_root + "/" + title_id + "/";
  if (auto data = read_file(directory + "param.json"))
    if (auto title = json_title(*data, title_id, locale))
      return title;
  if (title_id.substr(0, 4) == "CUSA")
    if (auto data = read_file(directory + "param.sfo"))
      if (auto title = sfo_title(*data, title_id))
        return title;
  return std::nullopt;
}

std::optional<GameTitle> platform_running_game() {
#ifdef PBS_PS5
  const int app_id = sceSystemServiceGetAppIdOfRunningBigApp();
  if (app_id <= 0) return std::nullopt;
  char title_id[16]{};
  if (sceLncUtilGetAppTitleId(static_cast<std::uint32_t>(app_id), title_id) != 0)
    return std::nullopt;
  const auto end = std::find(std::begin(title_id), std::end(title_id), '\0');
  if (end == std::end(title_id)) return std::nullopt;
  const std::string id(title_id, end);
  auto result = read_game_metadata("/user/appmeta", id);
  // PS4 title names live in system app metadata; /user/appmeta may contain
  // only icons and share assets for the same title.
  if (!result) result = read_game_metadata("/system_data/priv/appmeta", id);
  if (sceSystemServiceGetAppIdOfRunningBigApp() != app_id) return std::nullopt;
  return result;
#else
  return std::nullopt;
#endif
}
} // namespace pbsd
