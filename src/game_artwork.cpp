// SPDX-License-Identifier: GPL-3.0-or-later
#include "game_artwork.hpp"
#include "net.hpp"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pbsd {
namespace {
using Json = nlohmann::json;
constexpr std::size_t page_limit = 2 * 1024 * 1024;
constexpr std::string_view ps4_image_prefix =
    "https://gs2-sec.ww.prod.dl.playstation.net/gs2-sec/appkgo/prod/";

std::string ps4_metadata_url(std::string_view id) {
  if (!is_game_title_id(id) || !id.starts_with("CUSA")) return {};
  const auto np_title = std::string(id) + "_00";
  // Sony's public TMDB lookup convention uses this fixed title-hashing key.
  static constexpr unsigned char key[] = {
      0xf5, 0xde, 0x66, 0xd2, 0x68, 0x0e, 0x25, 0x5b, 0x2d, 0xf7, 0x9e, 0x74, 0xf8, 0x90, 0xeb, 0xf3,
      0x49, 0x26, 0x2f, 0x61, 0x8b, 0xca, 0xe2, 0xa9, 0xac, 0xcd, 0xee, 0x51, 0x56, 0xce, 0x8d, 0xf2,
      0xcd, 0xf2, 0xd4, 0x8c, 0x71, 0x17, 0x3c, 0xdc, 0x25, 0x94, 0x46, 0x5b, 0x87, 0x40, 0x5d, 0x19,
      0x7c, 0xf1, 0xae, 0xd3, 0xb7, 0xe9, 0x67, 0x1e, 0xeb, 0x56, 0xca, 0x67, 0x53, 0xc2, 0xe6, 0xb0,
  };
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned length = 0;
  if (!HMAC(EVP_sha1(), key, sizeof(key), reinterpret_cast<const unsigned char *>(np_title.data()),
            np_title.size(), digest, &length)) return {};
  std::string hex;
  constexpr char alphabet[] = "0123456789ABCDEF";
  for (unsigned i = 0; i < length; ++i) {
    hex += alphabet[digest[i] >> 4];
    hex += alphabet[digest[i] & 15];
  }
  return "https://tmdb.np.dl.playstation.net/tmdb2/" + np_title + "_" + hex + "/" + np_title + ".json";
}

std::string ps4_metadata_image(std::string_view body, const std::string &id) {
  const auto metadata = Json::parse(body, nullptr, false);
  if (!metadata.is_object() || metadata.value("npTitleId", Json()) != id + "_00") return {};
  const auto icons = metadata.find("icons");
  if (icons == metadata.end() || !icons->is_array()) return {};
  const auto title_prefix = std::string(ps4_image_prefix) + id + "_00/";
  for (const auto &entry : *icons) {
    if (!entry.is_object() || !entry.contains("icon") || !entry["icon"].is_string()) continue;
    auto image = entry["icon"].get<std::string>();
    if (image.starts_with("http://")) image.insert(4, "s");
    if (image.starts_with(title_prefix) && public_game_image_url(image)) return image;
  }
  return {};
}
bool digits(std::string_view s) {
  return !s.empty() && s.size() <= 12 && s.find_first_not_of("0123456789") == s.npos;
}
bool content_id(const GameTitle &game) {
  return is_game_content_id(game.content_id, game.title_id);
}
bool valid_store_key(std::string_view url) {
  constexpr std::string_view prefix = "https://store.playstation.com/";
  if (!url.starts_with(prefix)) return false;
  url.remove_prefix(prefix.size());
  const auto slash = url.find('/');
  if (slash == url.npos) return false;
  const auto locale = url.substr(0, slash);
  if (locale != "en-us" && locale != "en-gb" && locale != "en-hk" && locale != "ja-jp")
    return false;
  url.remove_prefix(slash + 1);
  if (url.starts_with("concept/")) return digits(url.substr(8));
  if (!url.starts_with("product/")) return false;
  const auto product = url.substr(8);
  return product.size() == 36 && is_game_content_id(product, product.substr(7, 9));
}
std::map<std::string, std::string> read_manifest(const std::string &path) {
  if (path.empty()) return {};
  const int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return {};
  struct Close { int fd; ~Close() { close(fd); } } closer{fd};
  constexpr std::size_t manifest_limit = 256 * 1024;
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      static_cast<std::uint64_t>(st.st_size) > manifest_limit) return {};
  std::string data(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t at = 0;
  while (at < data.size()) {
    const auto n = read(fd, data.data() + at, data.size() - at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return {};
    at += static_cast<std::size_t>(n);
  }
  char extra;
  ssize_t n;
  do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
  if (n != 0) return {};
  const auto root = Json::parse(data, nullptr, false);
  if (!root.is_object() || !root.contains("version") ||
      !root["version"].is_number_integer() || root["version"] != 1 ||
      !root.contains("images") || !root["images"].is_object() || root["images"].size() > 32)
    return {};
  std::map<std::string, std::string> images;
  for (const auto &[key, value] : root["images"].items()) {
    if ((!valid_store_key(key) && !is_game_title_id(key)) || !value.is_string()) continue;
    const auto &image = value.get_ref<const std::string &>();
    if (public_game_image_url(image)) images.emplace(key, image);
  }
  return images;
}
std::string attribute(std::string_view tag, std::string_view wanted) {
  std::size_t at = tag.find_first_of(" \t\r\n");
  while (at < tag.size()) {
    at = tag.find_first_not_of(" \t\r\n/", at);
    if (at == tag.npos) break;
    auto end = tag.find_first_of("= \t\r\n", at);
    if (end == tag.npos) break;
    auto name = lowercase(std::string(tag.substr(at, end - at)));
    at = tag.find_first_not_of(" \t\r\n", end);
    if (at == tag.npos || tag[at] != '=') continue;
    at = tag.find_first_not_of(" \t\r\n", at + 1);
    if (at == tag.npos) break;
    const char quote = tag[at];
    if (quote != '\'' && quote != '"') break;
    end = tag.find(quote, ++at);
    if (end == tag.npos) break;
    if (name == wanted) return std::string(tag.substr(at, end - at));
    at = end + 1;
  }
  return {};
}
std::string product_image(const Json &product) {
  if (!product.is_object() || product.value("@type", Json()) != "Product") return {};
  auto image = product.find("image");
  if (image != product.end() && image->is_string()) {
    const auto &url = image->get_ref<const std::string &>();
    if (public_game_image_url(url)) return url;
  }
  return {};
}
} // namespace

bool public_game_image_url(std::string_view url) {
  if (url.size() > 256 ||
      !(url.starts_with("https://image.api.playstation.com/") ||
        url.starts_with("https://image.dl.playstation.net/") ||
        url.starts_with(ps4_image_prefix))) return false;
  return std::all_of(url.begin(), url.end(), [](unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || std::string_view(":/._-?=&%+~").find(c) != std::string_view::npos;
  });
}
std::string game_store_url(const GameTitle &game) {
  if (digits(game.concept_id))
    return "https://store.playstation.com/en-us/concept/" + game.concept_id;
  if (!content_id(game)) return {};
  // Product IDs are regional; never guess a different title/edition ID.
  const auto region = game.content_id.substr(0, 2);
  const char *locale = region == "EP" ? "en-gb" : region == "HP" ? "en-hk" :
                       region == "JP" ? "ja-jp" : region == "UP" ? "en-us" : nullptr;
  return locale ? "https://store.playstation.com/" + std::string(locale) + "/product/" + game.content_id : "";
}
std::string parse_game_store_image(std::string_view page, const GameTitle &game) {
  if (page.size() > page_limit) return {};
  bool concept_matches = false;
  std::vector<Json> products;
  std::size_t at = 0;
  while ((at = page.find("<script", at)) != page.npos) {
    const auto end = page.find('>', at + 7);
    if (end == page.npos || end - at > 4096) break;
    const auto close = page.find("</script>", end + 1);
    if (close == page.npos) break;
    const auto tag = page.substr(at, end - at);
    const auto type = attribute(tag, "type");
    if (type == "application/ld+json" || attribute(tag, "id") == "__NEXT_DATA__") {
      auto data = Json::parse(page.substr(end + 1, close - end - 1), nullptr, false);
      if (attribute(tag, "id") == "__NEXT_DATA__" && data.is_object()) {
        const auto props = data.find("props");
        if (props != data.end() && props->is_object()) {
          const auto p = props->find("pageProps");
          concept_matches = p != props->end() && p->is_object() && digits(game.concept_id) &&
              p->value("conceptId", Json()) == game.concept_id;
        }
      } else if (type == "application/ld+json") {
        if (data.is_array()) for (auto &p : data) products.push_back(std::move(p));
        else products.push_back(std::move(data));
      }
    }
    at = close + 9;
  }
  for (const auto &p : products) {
    if (!p.is_object()) continue;
    if (!concept_matches && (!content_id(game) || p.value("sku", Json()) != game.content_id)) continue;
    if (auto url = product_image(p); !url.empty()) return url;
  }
  return {};
}
GameArtwork::GameArtwork(Fetch fetch, const std::string &cache_path) : fetch_(std::move(fetch)) {
  for (auto &[key, image] : read_manifest(cache_path))
    cache_[key] = {std::move(image), std::numeric_limits<std::uint64_t>::max()};
  if (!fetch_) fetch_ = [](const std::string &url) {
    auto response = https("GET", url, {}, {}, {}, 3000, page_limit);
    return response.status == 200 ? std::move(response.body) : std::string();
  };
}
GameArtwork::~GameArtwork() {
  { std::lock_guard lock(mutex_); stopping_ = true; pending_.reset(); }
  changed_.notify_one();
  if (worker_.joinable()) worker_.join();
}
std::string GameArtwork::image(const GameTitle &game) {
  if (!is_game_title_id(game.title_id)) return {};
  const auto store_url = game_store_url(game);
  const auto key = game.title_id.starts_with("CUSA") ? game.title_id : store_url;
  std::lock_guard lock(mutex_);
  if (const auto it = cache_.find(game.title_id);
      it != cache_.end() && it->second.expires == std::numeric_limits<std::uint64_t>::max())
    return it->second.image;
  if (store_url != key) {
    const auto it = cache_.find(store_url);
    if (it != cache_.end()) return it->second.image;
  }
  if (key.empty()) return {};
  const auto it = cache_.find(key);
  if (it != cache_.end() && monotonic_ms() < it->second.expires) return it->second.image;
  if (active_ != key && (!pending_ || pending_->title_id != game.title_id ||
                         game_store_url(*pending_) != store_url)) {
    pending_ = game;
    if (!worker_.joinable()) worker_ = std::thread(&GameArtwork::run, this);
    changed_.notify_one();
  }
  return {};
}
void GameArtwork::run() {
  std::unique_lock lock(mutex_);
  while (!stopping_) {
    changed_.wait(lock, [&] { return stopping_ || pending_.has_value(); });
    if (stopping_) break;
    auto game = std::move(*pending_);
    pending_.reset();
    const auto store_url = game_store_url(game);
    const bool ps4 = game.title_id.starts_with("CUSA");
    active_ = ps4 ? game.title_id : store_url;
    const auto key = active_;
    lock.unlock();
    std::string image;
    if (ps4) {
      try {
        const auto url = ps4_metadata_url(game.title_id);
        if (!url.empty()) image = ps4_metadata_image(fetch_(url), game.title_id);
      } catch (...) { }
    }
    if (image.empty() && !store_url.empty()) {
      try { image = parse_game_store_image(fetch_(store_url), game); } catch (...) { }
    }
    lock.lock();
    // Reserve room for up to 32 seeded covers plus 32 online results. Offline
    // covers must survive a lookup miss when the Store is blocked by DNS.
    if (!cache_.contains(key) && cache_.size() >= 64) {
      const auto transient = std::find_if(cache_.begin(), cache_.end(), [](const auto &entry) {
        return entry.second.expires != std::numeric_limits<std::uint64_t>::max();
      });
      if (transient != cache_.end()) cache_.erase(transient);
    }
    cache_[key] = {image, monotonic_ms() + (image.empty() ? 30ULL * 60 * 1000 : 24ULL * 60 * 60 * 1000)};
    active_.clear();
  }
}
} // namespace pbsd
