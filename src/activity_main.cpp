// SPDX-License-Identifier: GPL-3.0-or-later
#include "activity_session.hpp"
#include "activity_page.hpp"
#include "activity_qr.hpp"
#include "activity_script.hpp"
#include "net.hpp"
#include "platform.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#ifdef PBS_PS5
#include <sys/thr.h>
#endif
#include <unistd.h>

namespace {
using namespace pbsd;
constexpr int port = 9876;
struct Socket { int fd; ~Socket() { if (fd >= 0) close(fd); } };
volatile std::sig_atomic_t stopping = 0;

void reply(int fd, int code, std::string_view type, std::string_view body) {
  auto response = "HTTP/1.1 " + std::to_string(code) + (code == 200 ? " OK" : " Error") +
      "\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff"
      "\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer"
      "\r\nContent-Type: " + std::string(type) + "\r\nContent-Length: " +
      std::to_string(body.size()) + "\r\n\r\n";
  response += body;
  for (std::size_t at = 0; at < response.size();) {
    const auto count = send(fd, response.data() + at, response.size() - at, 0);
    if (count <= 0) return;
    at += count;
  }
}

void serve(int fd, ActivitySession &session) {
  constexpr std::size_t limit = 16 * 1024;
  const timeval timeout{2, 0};
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  const auto deadline = monotonic_ms() + 3000;
  std::string input;
  auto read_more = [&] {
    const auto now = monotonic_ms();
    if (now >= deadline || input.size() >= limit) return false;
    pollfd waiting{fd, POLLIN, 0};
    if (poll(&waiting, 1, static_cast<int>(deadline - now)) <= 0) return false;
    char buffer[2048];
    const auto n = recv(fd, buffer, std::min(sizeof(buffer), limit - input.size()), 0);
    if (n <= 0) return false;
    input.append(buffer, n);
    return true;
  };
  std::size_t end;
  while ((end = input.find("\r\n\r\n")) == std::string::npos)
    if (!read_more()) return;
  std::istringstream lines(input.substr(0, end));
  std::string method, path, version, line;
  if (!std::getline(lines, line)) return;
  std::istringstream request(line);
  if (!(request >> method >> path >> version)) return;
  std::map<std::string, std::string> headers;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto colon = line.find(':');
    if (colon == line.npos) return;
    const auto value = line.find_first_not_of(" \t", colon + 1);
    if (!headers.emplace(lowercase(line.substr(0, colon)),
                         value == line.npos ? "" : line.substr(value)).second) return;
  }

  // Permit only the numeric listener address to prevent DNS rebinding.
  sockaddr_in local{};
  socklen_t size = sizeof(local);
  char address[INET_ADDRSTRLEN];
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &size) ||
      !inet_ntop(AF_INET, &local.sin_addr, address, sizeof(address))) return;
  const auto host = std::string(address) + ":" + std::to_string(port);
  if (headers["host"] != host) {
    reply(fd, 403, "text/plain", "Open this page using the console's numeric IP address.");
    return;
  }
  if (method == "GET") {
    if (path == "/") return reply(fd, 200, "text/html; charset=utf-8", activity_page);
    if (path == "/activity.js") return reply(fd, 200, "text/javascript", activity_script);
    if (path == "/qr.js") return reply(fd, 200, "text/javascript", activity_qr);
    if (path == "/status") return reply(fd, 200, "application/json", session.status().dump());
  }
  if (method == "POST") {
    if (headers["origin"] != "http://" + host || headers["x-activity-request"] != "1" ||
        headers.contains("transfer-encoding")) {
      reply(fd, 403, "text/plain", "Open the dashboard to perform this action.");
      return;
    }
    try {
      const auto length_text = headers["content-length"];
      if (length_text.empty() || length_text.find_first_not_of("0123456789") != length_text.npos)
        throw std::runtime_error("Invalid request length");
      const auto length = std::stoul(length_text);
      if (length > limit - end - 4) throw std::runtime_error("Request too large");
      while (input.size() < end + 4 + length)
        if (!read_more()) return;
      if (path == "/signin") session.sign_in();
      else if (path == "/cancel") session.cancel();
      else if (path == "/signout") session.sign_out();
      else if (path == "/verify") session.verify(Json::parse(input.substr(end + 4, length)));
      else return reply(fd, 404, "text/plain", "Not found");
      return reply(fd, 200, "application/json", "{}");
    } catch (const std::exception &e) {
      return reply(fd, 400, "application/json", Json{{"error", e.what()}}.dump());
    }
  }
  reply(fd, 404, "text/plain", "Not found");
}
}

int main(int argc, char **argv) {
  try {
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, [](int) { stopping = 1; });
    std::signal(SIGTERM, [](int) { stopping = 1; });
    pbsd::initialize_platform_random();
#ifdef PBS_PS5
    if (thr_set_name(-1, "ps5activity.elf") != 0)
      std::perror("Could not set PS5 Game Activity task name");
    const std::string directory = "/data/ps5-game-activity";
#else
    const std::string directory = argc > 1 ? argv[1] : "./game-activity-data";
#endif
    Socket listener{socket(AF_INET, SOCK_STREAM, 0)};
    if (listener.fd < 0) throw std::runtime_error("Could not open dashboard socket");
    const int yes = 1;
    setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{};
#ifdef PBS_PS5
    address.sin_len = sizeof(address);
#endif
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) ||
        listen(listener.fd, 8)) throw std::runtime_error("Could not listen on port 9876");
    pbsd::ActivitySession session(directory);
    std::puts("PS5 Game Activity dashboard listening on port 9876");
    while (!stopping) {
      pollfd waiting{listener.fd, POLLIN, 0};
      if (poll(&waiting, 1, 250) <= 0) continue;
      Socket client{accept(listener.fd, nullptr, nullptr)};
      if (client.fd >= 0) serve(client.fd, session);
    }
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
