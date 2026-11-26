// SPDX-License-Identifier: GPL-3.0-or-later
#include "activity_session.hpp"
#include "activity_settings.hpp"
#include "net.hpp"
#include <chrono>
#include <future>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

namespace pbsd {
ActivitySession::ActivitySession(const std::string &directory)
    : account_store_(directory), game_artwork_({}, directory + "/game-artwork.json") {
  launch(false);
}
ActivitySession::~ActivitySession() { stop(); }

void ActivitySession::stop() {
  stopping_ = true;
  if (worker_.joinable()) worker_.join();
  verification_.clear();
  secure_erase(token_.data(), token_.size());
  token_.clear();
}

void ActivitySession::set_state(std::string state, std::string error) {
  std::lock_guard lock(mutex_);
  state_ = std::move(state);
  error_ = std::move(error);
}

Json ActivitySession::status() {
  const auto verification = verification_.status(monotonic_ms());
  std::lock_guard lock(mutex_);
  return {{"state", state_}, {"error", error_}, {"username", username_},
          {"qr_url", qr_url_}, {"verification", verification}, {"saved", account_store_.saved()},
          {"game", activity_game_ ? Json{{"name", activity_game_->name},
             {"image_url", activity_game_->image_url}} : Json(nullptr)}};
}

void ActivitySession::verify(const Json &body) {
  verification_.submit(body.at("challenge_id"), body.at("solution"), monotonic_ms());
}

void ActivitySession::cancel() {
  const auto state = status().at("state");
  if (state != "linking" && state != "verification_required" && state != "verifying") return;
  stop();
  std::lock_guard lock(mutex_);
  qr_url_.clear();
  state_ = "disconnected";
  error_.clear();
}

void ActivitySession::sign_out() {
  stop();
  {
    std::lock_guard lock(mutex_);
    username_.clear();
    qr_url_.clear();
    activity_game_.reset();
    state_ = "disconnected";
    error_.clear();
  }
  account_store_.forget();
}

void ActivitySession::sign_in() {
  {
    std::lock_guard lock(mutex_);
    if (state_ != "disconnected" && state_ != "error") return;
  }
  if (account_store_.saved()) throw std::runtime_error("Sign out before linking another account");
  launch(true);
}

void ActivitySession::launch(bool linking) {
  stop();
  set_state(linking ? "linking" : "connecting");
  stopping_ = false;
  worker_ = std::thread([this, linking] {
    try {
      if (linking) qr_login();
      else if (auto saved = account_store_.restore()) token_ = std::move(*saved);
      else { set_state("disconnected"); return; }
      while (!stopping_) {
        try {
          gateway();
        } catch (const WebSocketClose &closed) {
          if (closed.code() == 4004)
            throw std::runtime_error("Discord rejected the login. Sign out and link again.");
          if (!account_store_.saved()) throw;
        } catch (const std::exception &) {
          if (!account_store_.saved()) throw;
        }
        if (stopping_) break;
        {
          std::lock_guard lock(mutex_);
          state_ = "connecting";
          activity_game_.reset();
        }
        for (int i = 0; i < 50 && !stopping_; ++i)
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    } catch (const std::exception &e) {
      verification_.clear();
      std::lock_guard lock(mutex_);
      qr_url_.clear();
      activity_game_.reset();
      if (!stopping_) { state_ = "error"; error_ = e.what(); }
    }
    secure_erase(token_.data(), token_.size());
    token_.clear();
  });
}

static Bytes rsa_decrypt(EVP_PKEY *key, const std::string &text) {
  auto cipher = unbase64(text);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
  if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0)
    throw std::runtime_error("QR decryption setup failed");
  std::size_t n = 0;
  if (EVP_PKEY_decrypt(ctx.get(), nullptr, &n, cipher.data(), cipher.size()) <=
          0 ||
      n > 4096)
    throw std::runtime_error("Invalid QR handshake");
  Bytes plain(n);
  if (EVP_PKEY_decrypt(ctx.get(), plain.data(), &n, cipher.data(),
                       cipher.size()) <= 0)
    throw std::runtime_error("QR handshake decryption failed");
  plain.resize(n);
  return plain;
}
void ActivitySession::qr_login() {
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> keyctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
  EVP_PKEY *raw = nullptr;
  if (!keyctx || EVP_PKEY_keygen_init(keyctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(keyctx.get(), 2048) <= 0 ||
      EVP_PKEY_keygen(keyctx.get(), &raw) <= 0)
    throw std::runtime_error("QR signing key generation failed");
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw,
                                                          EVP_PKEY_free);
  int length = i2d_PUBKEY(raw, nullptr);
  if (length <= 0)
    throw std::runtime_error("QR public key unavailable");
  Bytes der(length);
  auto *ptr = der.data();
  i2d_PUBKEY(raw, &ptr);
  WebSocket ws;
  ws.connect("wss://remote-auth-gateway.discord.gg/?v=2",
             "https://discord.com", 65536);
  std::uint64_t interval = 0, next = 0, deadline = monotonic_ms() + 180000;
  bool ack = true;
  std::string token;
  auto service_gateway = [&]() -> std::optional<WebSocket::Message> {
    auto now = monotonic_ms();
    if (interval && now >= next) {
      if (!ack)
        throw std::runtime_error("QR connection expired; link again");
      ws.text(Json{{"op", "heartbeat"}}.dump());
      ack = false;
      next = now + interval;
    }
    auto message = ws.receive(now + 50);
    if (message && !message->binary) {
      auto event = Json::parse(message->data);
      if (event.value("op", "") == "heartbeat_ack") ack = true;
      if (event.value("op", "") == "cancel")
        throw std::runtime_error("Account linking cancelled on your phone");
    }
    return message;
  };
  while (!stopping_ && monotonic_ms() < deadline) {
    auto now = monotonic_ms();
    auto message = service_gateway();
    if (!message || message->binary)
      continue;
    auto j = Json::parse(message->data);
    auto op = j.value("op", "");
    if (op == "hello") {
      interval = j.at("heartbeat_interval");
      if (interval < 1000 || interval > 120000)
        throw std::runtime_error("Invalid QR heartbeat");
      next = now + interval;
      ws.text(
          Json{{"op", "init"}, {"encoded_public_key", base64(der)}}.dump());
    } else if (op == "heartbeat_ack")
      ack = true;
    else if (op == "nonce_proof") {
      auto nonce = rsa_decrypt(raw, j.at("encrypted_nonce"));
      unsigned char hash[32];
      SHA256(nonce.data(), nonce.size(), hash);
      secure_erase(nonce.data(), nonce.size());
      ws.text(Json{{"op", "nonce_proof"}, {"proof", base64(hash, true)}}
                  .dump());
    } else if (op == "pending_remote_init") {
      auto fingerprint = j.at("fingerprint").get<std::string>();
      if (fingerprint.size() > 256 ||
          fingerprint.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
                                        "ijklmnopqrstuvwxyz0123456789-_") !=
              std::string::npos)
        throw std::runtime_error("Invalid QR link");
      std::lock_guard lock(mutex_);
      qr_url_ = "https://discord.com/ra/" + fingerprint;
    } else if (op == "pending_login") {
      auto ticket = j.at("ticket").get<std::string>();
      if (ticket.empty() || ticket.size() > 4096)
        throw std::runtime_error("QR ticket too large");
      std::map<std::string, std::string> headers;
      unsigned challenges = 0;
      bool qr_gateway_open = true;
      for (;;) {
        if (stopping_) return;
        auto response = https("POST",
            "https://discord.com/api/v10/users/@me/remote-auth/login",
            Json{{"ticket", ticket}}.dump(), {}, headers, 12000);
        for (auto &[name, value] : headers)
          secure_erase(value.data(), value.size());
        headers.clear();
        if (stopping_) return;
        if (response.status == 429)
          throw std::runtime_error("Discord login rate limit; wait before linking again");
        auto result = Json::parse(response.body);
        if (response.status == 200 && result.contains("encrypted_token")) {
          auto plain = rsa_decrypt(raw, result.at("encrypted_token"));
          token.assign(plain.begin(), plain.end());
          secure_erase(plain.data(), plain.size());
          break;
        }
        if (!result.contains("captcha_key") && !result.contains("captcha_sitekey"))
          throw std::runtime_error("Discord rejected the confirmed QR login (HTTP " +
                                   std::to_string(response.status) + ")");
        if (++challenges > 3)
          throw std::runtime_error("Discord did not accept verification; link again later");
        verification_.issue(result, deadline);
        {
          std::lock_guard lock(mutex_);
          qr_url_.clear();
          state_ = "verification_required";
          error_.clear();
        }
        // A user-completed response permits one exchange of this ticket.
        while (!stopping_ && monotonic_ms() < deadline) {
          if (auto submitted = verification_.take(monotonic_ms())) {
            headers = std::move(*submitted);
            break;
          }
          if (qr_gateway_open) {
            try { service_gateway(); }
            catch (const WebSocketClose &closed) {
              if (closed.code() != 1000 && closed.code() != 1001) throw;
              qr_gateway_open = false;
              ws.close();
            }
          } else std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (stopping_) return;
        if (headers.empty())
          throw std::runtime_error("Login verification expired; link again");
        set_state("verifying");
      }
      break;
    } else if (op == "cancel")
      throw std::runtime_error("Account linking cancelled on your phone");
  }
  ws.close();
  verification_.clear();
  if (stopping_)
    return;
  if (token.size() < 20 || token.size() > 4096)
    throw std::runtime_error("QR code expired; link again");
  {
    std::lock_guard lock(mutex_);
    token_ = std::move(token);
    qr_url_.clear();
    state_ = "connecting";
  }
}

void ActivitySession::gateway() {
  auto token = token_;
  struct EraseToken {
    std::string &token;
    ~EraseToken() { secure_erase(token.data(), token.size()); }
  } erase_token{token};
  WebSocket ws;
  ws.connect("wss://gateway.discord.gg/?v=10&encoding=json");
  auto send = [&](int op, const Json &d) {
    ws.text(Json{{"op", op}, {"d", d}}.dump());
  };
  std::int64_t sequence = -1;
  bool ready = false, heartbeat_ack = true;
  std::uint64_t interval = 0, next_heartbeat = 0, next_activity_poll = 0;
  const auto ready_deadline = monotonic_ms() + 30000;
  Json last_activities = Json::array();
  std::string requested_image, activity_asset;
  std::uint64_t retry_asset_at = 0;
  // The request uses the Gateway account token. The future joins before that
  // token goes out of scope, including on disconnect.
  std::future<std::string> asset_lookup;
  while (!stopping_) {
    const auto now = monotonic_ms();
    if (!ready && now > ready_deadline)
      throw std::runtime_error("Discord connection timed out");
    if (interval && now >= next_heartbeat) {
      if (!heartbeat_ack) throw std::runtime_error("Discord connection lost");
      send(1, sequence < 0 ? Json(nullptr) : Json(sequence));
      heartbeat_ack = false;
      next_heartbeat = now + interval;
    }
    if (ready && now >= next_activity_poll) {
      next_activity_poll = now + 5000;
      auto game = platform_running_game();
      if (game) game->image_url = game_artwork_.image(*game);
      {
        std::lock_guard lock(mutex_);
        activity_game_ = game;
      }
      const auto artwork = game ? game->image_url : std::string();
      if (asset_lookup.valid() &&
          asset_lookup.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        auto asset = asset_lookup.get();
        if (requested_image == artwork) activity_asset = std::move(asset);
      }
      if (!asset_lookup.valid() && !artwork.empty() &&
          (requested_image != artwork || (activity_asset.empty() && now >= retry_asset_at))) {
        requested_image = artwork;
        activity_asset.clear();
        retry_asset_at = now + 60'000;
        try {
          asset_lookup = std::async(std::launch::async, [artwork, &token] {
            try {
              const std::string endpoint = std::string("https://discord.com/api/v10/applications/") +
                  game_activity_application_id + "/external-assets";
              const auto body = Json{{"urls", Json::array({artwork})}}.dump();
              const auto response = https("POST", endpoint, body, token, {}, 3000, 16 * 1024);
              if (response.status == 200)
                return discord_game_image(Json::parse(response.body, nullptr, false));
            } catch (...) { }
            return std::string{};
          });
        } catch (const std::system_error &) { }
      }
      auto presence = game_activity_presence(true, game,
          artwork == requested_image ? activity_asset : std::string{});
      if (presence.at("activities") != last_activities) {
        send(3, presence);
        last_activities = presence.at("activities");
      }
    }
    if (auto message = ws.receive(now + 20)) {
      if (message->binary)
        throw std::runtime_error(
            "Unexpected compressed account Gateway message");
      auto packet = Json::parse(message->data);
      int op = packet.at("op");
      if (packet.contains("s") && !packet["s"].is_null())
        sequence = packet["s"].get<std::int64_t>();
      auto &d = packet["d"];
      if (op == 10) {
        interval = d.at("heartbeat_interval");
        if (interval < 1000 || interval > 120000)
          throw std::runtime_error("Invalid account heartbeat");
        next_heartbeat = now + interval;
        send(2, {{"token", token},
                 {"capabilities", 16381},
                 {"properties",
                  {{"os", "Linux"},
                   {"browser", "PS5 Game Activity"},
                   {"device", "PS5"}}},
                 {"compress", false},
                 {"presence",
                  {{"status", "online"},
                   {"since", 0},
                   {"activities", Json::array()},
                   {"afk", false}}},
                 {"client_state", {{"guild_versions", Json::object()}}}});
      } else if (op == 11)
        heartbeat_ack = true;
      else if (op == 1)
        send(1, sequence < 0 ? Json(nullptr) : Json(sequence));
      else if (op == 7 || op == 9)
        throw std::runtime_error(
            "Discord requested a fresh account connection");
      else if (op == 0 && !ready && packet.value("t", "") == "READY") {
        const auto username = d.at("user").at("username").get<std::string>();
        if (username.empty()) throw std::runtime_error("Discord username missing");
        if (stopping_) break;
        if (!account_store_.saved()) account_store_.save(token);
        std::lock_guard lock(mutex_);
        username_ = username;
        state_ = "ready";
        ready = true;
      }
    }
  }
  if (ready && !last_activities.empty()) send(3, game_activity_presence(false, {}));
}
} // namespace pbsd
