// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "types.hpp"
#include <functional>
#include <map>
#include <memory>
#include <openssl/ssl.h>
#include <optional>
#include <stdexcept>
namespace pbsd {
struct Url {
  std::string host, path;
  int port{443};
  static Url parse(const std::string &);
  std::string authority() const;
};
struct HttpResponse {
  int status{};
  std::map<std::string, std::string> headers;
  std::string body;
};
using Context = std::shared_ptr<SSL_CTX>;
Context client_context();
Context server_context(const std::string &directory, std::string &fingerprint,
                       const std::string &address = "127.0.0.1");
class Tls {
public:
  Tls() = default;
  ~Tls();
  Tls(const Tls &) = delete;
  Tls &operator=(const Tls &) = delete;
  // Optional absolute monotonic-ms deadline. System DNS cannot be cancelled;
  // its elapsed time is checked before any subsequent connection work.
  void connect(const Url &url, Context context, std::uint64_t deadline = 0);
  void accept(int socket, Context context);
  void write(View data, std::uint64_t deadline);
  void write(const std::string &data, std::uint64_t deadline);
  std::optional<Bytes> read(std::size_t limit, std::uint64_t deadline);
  void close();
  int fd() const { return socket_; }

private:
  int socket_{-1};
  SSL *ssl_{};
  Context context_;
};
// A nonzero timeout is one shared request budget, including synchronous DNS
// elapsed time (DNS itself cannot be cancelled). The decoded response body
// limit must be 1 byte..16 MiB; headers and chunk framing have bounded extra space.
HttpResponse https(const std::string &method, const std::string &url,
                   const std::string &body = {}, const std::string &token = {},
                   const std::map<std::string, std::string> &verification_headers = {},
                   std::uint64_t timeout_ms = 0,
                   std::size_t response_limit = 16 * 1024 * 1024);
// A protocol close is distinct from a TLS disconnect. The peer's reason is
// limited by the 125-byte control-frame budget and normalized for display.
class WebSocketClose : public std::runtime_error {
public:
  static WebSocketClose from_payload(View payload);
  std::optional<std::uint16_t> code() const { return code_; }
  const std::string &reason() const { return reason_; }

private:
  WebSocketClose(std::optional<std::uint16_t> code, const std::string &reason);
  std::optional<std::uint16_t> code_;
  std::string reason_;
};
class WebSocket {
public:
  void connect(const std::string &url,
               const std::string &origin = "https://discord.com",
               std::size_t limit = 8 * 1024 * 1024);
  struct Message {
    bool binary{};
    Bytes data;
  };
  std::optional<Message> receive(std::uint64_t deadline);
  void text(const std::string &text);
  void binary(View data);
  void close();

private:
  Tls tls_;
  Bytes buffered_, message_;
  bool fragmented_{}, binary_{};
  std::size_t limit_{8 * 1024 * 1024};
  void send(std::uint8_t opcode, View data);
};
class Udp {
public:
  Udp() = default;
  ~Udp();
  Udp(const Udp &) = delete;
  Udp &operator=(const Udp &) = delete;
  void connect(const std::string &ip, int port);
  void send(View data);
  std::optional<Bytes> receive();
  void close();

private:
  int socket_{-1};
};
std::string base64(View data, bool url = false);
Bytes unbase64(const std::string &data);
Bytes random_bytes(std::size_t count);
std::string random_hex(std::size_t count);
std::string lowercase(std::string text);
bool constant_equal(const std::string &a, const std::string &b);
bool media_host(const std::string &host);
// Accept a gateway authority or WSS URL, retaining its supplied TLS port.
// Legacy port 80 alone is upgraded to 443; the returned URL uses protocol v8.
std::string media_gateway_endpoint(const std::string &endpoint);
} // namespace pbsd
