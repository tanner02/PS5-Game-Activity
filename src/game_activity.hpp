// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace pbsd {
struct GameTitle {
  std::string title_id, name;
  std::string content_id{}, concept_id{}, image_url{};
};
// A conservative retail-shaped title ID filter, not proof of game/focus status.
bool is_game_title_id(std::string_view title_id);
bool is_game_content_id(std::string_view content_id, std::string_view title_id);
std::optional<GameTitle> read_game_metadata(const std::string &appmeta_root,
                                          const std::string &title_id,
                                          const std::string &locale = "en-US");
// Queries the running big application through ordinary system-service APIs.
std::optional<GameTitle> platform_running_game();
} // namespace pbsd
