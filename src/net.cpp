// SPDX-License-Identifier: GPL-3.0-or-later
#include "net.hpp"
#include "ca_bundle.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
namespace pbsd {
std::uint64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
void secure_erase(void *p, std::size_t n) { OPENSSL_cleanse(p, n); }
static void fail(const char *m) { throw std::runtime_error(m); }
class PeerClosed : public std::runtime_error {
public:
  PeerClosed() : std::runtime_error("TLS peer closed") {}
};
std::string lowercase(std::string s) {
  for (auto &c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}
Bytes random_bytes(std::size_t n) {
  if (n > 1048576)
    fail("Random request too large");
  Bytes b(n);
  if (RAND_bytes(b.data(), static_cast<int>(n)) != 1)
    fail("Secure random generator failed");
  return b;
}
std::string random_hex(std::size_t n) {
  auto b = random_bytes(n);
  std::string s;
  for (auto v : b) {
    s += "0123456789abcdef"[v >> 4];
    s += "0123456789abcdef"[v & 15];
  }
  return s;
}
bool constant_equal(const std::string &a, const std::string &b) {
  return a.size() == b.size() &&
         CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
std::string base64(View b, bool url) {
  std::string out(4 * ((b.size() + 2) / 3), '\0');
  if (!b.empty())
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), b.data(),
                    static_cast<int>(b.size()));
  if (url) {
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    while (!out.empty() && out.back() == '=')
      out.pop_back();
  }
  return out;
}
Bytes unbase64(const std::string &s) {
  if (s.size() > 16 * 1024 * 1024)
    fail("Base64 input too large");
  std::string p = s;
  std::replace(p.begin(), p.end(), '-', '+');
  std::replace(p.begin(), p.end(), '_', '/');
  for (char c : p)
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '/' &&
        c != '=')
      fail("Invalid base64");
  while (p.size() % 4)
    p += '=';
  Bytes b(3 * (p.size() / 4));
  if (p.empty())
    return b;
  int n = EVP_DecodeBlock(b.data(),
                          reinterpret_cast<const unsigned char *>(p.data()),
                          static_cast<int>(p.size()));
  if (n < 0)
    fail("Invalid base64");
  if (p.back() == '=')
    --n;
  if (p.size() > 1 && p[p.size() - 2] == '=')
    --n;
  if (n < 0)
    fail("Invalid base64");
  b.resize(n);
  return b;
}
Url Url::parse(const std::string &s) {
  auto i = s.find("://");
  if (i == std::string::npos ||
      (s.substr(0, i) != "https" && s.substr(0, i) != "wss"))
    fail("TLS URL required");
  auto end = s.find('/', i + 3);
  std::string host = s.substr(
      i + 3, end == std::string::npos ? std::string::npos : end - i - 3);
  if (host.empty() || host.find_first_of("@\\\r\n#? ") != std::string::npos)
    fail("Invalid URL authority");
  Url u;
  auto colon = host.find(':');
  if (colon != std::string::npos) {
    auto p = host.substr(colon + 1);
    if (p.empty() || p.find_first_not_of("0123456789") != std::string::npos)
      fail("Invalid port");
    u.port = std::stoi(p);
    host.resize(colon);
  }
  if (u.port < 1 || u.port > 65535)
    fail("Invalid port");
  u.host = lowercase(host);
  u.path = end == std::string::npos ? "/" : s.substr(end);
  if (u.path.find_first_of("\r\n ") != std::string::npos)
    fail("Invalid URL path");
  return u;
}
std::string Url::authority() const {
  return host + (port == 443 ? "" : ":" + std::to_string(port));
}
bool media_host(const std::string &host) {
  // Discord owns every domain below and serves the media gateway over TLS
  // on all of them. The real anchor is the TLS handshake: the connection
  // must present a certificate for exactly this hostname issued under the
  // pinned CA set, so a hostile gateway cannot redirect media traffic.
  for (auto exact : {"discord.media", "discord.gg", "discord.com"}) {
    if (host == exact)
      return true;
  }
  for (auto suffix : {".discord.media", ".discord.gg", ".discord.com",
                      ".discordapp.com", ".discordapp.net"}) {
    std::string x = suffix;
    if (host.size() > x.size() && host.ends_with(x))
      return true;
  }
  return false;
}
std::string media_gateway_endpoint(const std::string &endpoint) {
  if (endpoint.find("://") != std::string::npos &&
      !endpoint.starts_with("wss://"))
    fail("WSS media gateway URL required");
  auto url = Url::parse(endpoint.starts_with("wss://") ? endpoint
                                                       : "wss://" + endpoint);
  if (url.host.empty() ||
      url.host.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-.") !=
          std::string::npos ||
      (url.path != "/" && url.path != "/?v=8"))
    fail("Invalid media gateway endpoint");
#ifndef PBSD_TESTING
  if (!media_host(url.host))
    throw std::runtime_error("Untrusted Discord media endpoint: wss://" +
                             url.host + ":" + std::to_string(url.port));
#endif
  // Historical gateway authorities advertised :80 for a TLS service on 443.
  // Compare the complete parsed port so :800 and :8080 stay untouched.
  if (url.port == 80)
    url.port = 443;
  return "wss://" + url.host + ":" + std::to_string(url.port) + "/?v=8";
}
static void nonblock(int fd) {
  int f = fcntl(fd, F_GETFL, 0);
  if (f < 0 || fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0)
    fail("Socket configuration failed");
}
static bool wait_fd(int fd, bool write, std::uint64_t end) {
  for (;;) {
    const auto now = monotonic_ms();
    if (now >= end)
      return false;
    pollfd p{fd, static_cast<short>(write ? POLLOUT : POLLIN), 0};
    int wait =
        static_cast<int>(std::min<std::uint64_t>(end - now, 1000));
    int r = poll(&p, 1, std::max(1, wait));
    if (r > 0)
      return true;
    if (r < 0 && errno != EINTR)
      fail("Socket wait failed");
  }
}
Context client_context() {
  static Context context = []() {
    Context ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx)
      fail("TLS initialization failed");
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    BIO *bio = BIO_new_mem_buf(PBSD_CA_BUNDLE, -1);
    if (!bio)
      fail("CA bundle unavailable");
    int count = 0;
    while (auto *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
      X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.get()), cert);
      X509_free(cert);
      ++count;
    }
    BIO_free(bio);
    ERR_clear_error();
    if (!count)
      fail("CA bundle empty");
#ifdef PBSD_TESTING
    if (const char *ca = std::getenv("PBSD_TEST_CA"))
      if (SSL_CTX_load_verify_locations(ctx.get(), ca, nullptr) != 1)
        fail("Local test CA could not load");
#endif
    return ctx;
  }();
  return context;
}
Context server_context(const std::string &dir, std::string &fingerprint,
                       const std::string &address) {
  mkdir(dir.c_str(), 0700);
  auto certfile = dir + "/server.crt", keyfile = dir + "/server.key";
  std::ifstream ck(certfile), kk(keyfile);
  if (!ck.good() || !kk.good()) {
    EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY *key = nullptr;
    X509 *cert = X509_new();
    if (!keyctx || !cert || EVP_PKEY_keygen_init(keyctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyctx, NID_X9_62_prime256v1) <=
            0 ||
        EVP_PKEY_keygen(keyctx, &key) <= 0)
      fail("Certificate key generation failed");
    EVP_PKEY_CTX_free(keyctx);
    X509_set_version(cert, 2);
    auto serial = random_bytes(8);
    serial[0] &= 0x7f;
    BIGNUM *bn = BN_bin2bn(serial.data(), 8, nullptr);
    ASN1_INTEGER *sn = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    X509_set_serialNumber(cert, sn);
    ASN1_INTEGER_free(sn);
    X509_gmtime_adj(X509_get_notBefore(cert), -86400);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, key);
    auto *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>("PBS Discord Console"), -1, -1,
        0);
    X509_set_issuer_name(cert, name);
    std::string san = "DNS:ps5.local,DNS:localhost,IP:127.0.0.1";
    in_addr ip{};
    if (address != "127.0.0.1" && inet_pton(AF_INET, address.c_str(), &ip) == 1)
      san += ",IP:" + address;
    auto *ext =
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.data());
    if (ext) {
      X509_add_ext(cert, ext, -1);
      X509_EXTENSION_free(ext);
    }
    if (X509_sign(cert, key, EVP_sha256()) <= 0)
      fail("Certificate signing failed");
    FILE *k = fopen(keyfile.c_str(), "wb");
    if (!k)
      fail("Cannot save server key");
    chmod(keyfile.c_str(), 0600);
    bool ok = PEM_write_PrivateKey(k, key, nullptr, nullptr, 0, nullptr,
                                   nullptr) == 1;
    fclose(k);
    FILE *c = fopen(certfile.c_str(), "wb");
    if (!c)
      fail("Cannot save certificate");
    ok = ok && PEM_write_X509(c, cert) == 1;
    fclose(c);
    X509_free(cert);
    EVP_PKEY_free(key);
    if (!ok)
      fail("Cannot save HTTPS identity");
  }
  Context ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
  if (!ctx)
    fail("HTTPS context failed");
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
  if (SSL_CTX_use_certificate_chain_file(ctx.get(), certfile.c_str()) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx.get(), keyfile.c_str(),
                                  SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(ctx.get()) != 1)
    fail("HTTPS identity load failed");
  auto *cert = SSL_CTX_get0_certificate(ctx.get());
  unsigned char digest[32];
  unsigned int len = 0;
  if (X509_digest(cert, EVP_sha256(), digest, &len) != 1)
    fail("Certificate fingerprint failed");
  for (unsigned i = 0; i < len; ++i) {
    if (i)
      fingerprint += ':';
    fingerprint += "0123456789ABCDEF"[digest[i] >> 4];
    fingerprint += "0123456789ABCDEF"[digest[i] & 15];
  }
  return ctx;
}
Tls::~Tls() { close(); }
void Tls::close() {
  if (ssl_) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
  if (socket_ >= 0) {
    ::close(socket_);
    socket_ = -1;
  }
  context_.reset();
}
void Tls::connect(const Url &u, Context context, std::uint64_t deadline) {
  close();
  context_ = std::move(context);
  const bool supplied_deadline = deadline != 0;
  if (supplied_deadline && monotonic_ms() >= deadline)
    fail("TLS connection timed out");
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *addresses = nullptr;
  if (getaddrinfo(u.host.c_str(), std::to_string(u.port).c_str(), &hints,
                  &addresses))
    fail("DNS lookup failed");
  // getaddrinfo is synchronous and cannot be interrupted here. A supplied
  // request deadline still includes DNS time: never start a connection late.
  if (!supplied_deadline)
    deadline = monotonic_ms() + 12000;
  if (monotonic_ms() >= deadline) {
    freeaddrinfo(addresses);
    fail("TLS connection timed out");
  }
  for (auto *a = addresses; a; a = a->ai_next) {
    if (monotonic_ms() >= deadline)
      break;
    int s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (s < 0)
      continue;
    try {
      nonblock(s);
      int rc = ::connect(s, a->ai_addr, a->ai_addrlen);
      if (rc == 0 || (errno == EINPROGRESS && wait_fd(s, true, deadline))) {
        int err = 0;
        socklen_t len = sizeof err;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && !err) {
          socket_ = s;
          break;
        }
      }
    } catch (...) {
      ::close(s);
      freeaddrinfo(addresses);
      throw;
    }
    ::close(s);
  }
  freeaddrinfo(addresses);
  if (socket_ < 0)
    fail("TLS connection failed");
  ssl_ = SSL_new(context_.get());
  if (!ssl_ || SSL_set_fd(ssl_, socket_) != 1 ||
      SSL_set_tlsext_host_name(ssl_, u.host.c_str()) != 1 ||
      SSL_set1_host(ssl_, u.host.c_str()) != 1)
    fail("TLS hostname setup failed");
  for (;;) {
    if (monotonic_ms() >= deadline)
      fail("TLS handshake timed out");
    int rc = SSL_connect(ssl_);
    if (rc == 1)
      break;
    int e = SSL_get_error(ssl_, rc);
    if ((e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) ||
        !wait_fd(socket_, e == SSL_ERROR_WANT_WRITE, deadline))
      fail("TLS handshake or certificate validation failed");
  }
  if (SSL_get_verify_result(ssl_) != X509_V_OK)
    fail("TLS certificate rejected");
  if (supplied_deadline && monotonic_ms() >= deadline)
    fail("TLS connection timed out");
}
void Tls::accept(int s, Context context) {
  close();
  socket_ = s;
  context_ = std::move(context);
  nonblock(s);
  ssl_ = SSL_new(context_.get());
  if (!ssl_ || SSL_set_fd(ssl_, s) != 1)
    fail("HTTPS connection failed");
  auto end = monotonic_ms() + 5000;
  for (;;) {
    int rc = SSL_accept(ssl_);
    if (rc == 1)
      return;
    int e = SSL_get_error(ssl_, rc);
    if ((e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) ||
        !wait_fd(s, e == SSL_ERROR_WANT_WRITE, end))
      fail("HTTPS handshake failed");
  }
}
void Tls::write(const std::string &s, std::uint64_t end) {
  write(View(reinterpret_cast<const std::uint8_t *>(s.data()), s.size()), end);
}
void Tls::write(View b, std::uint64_t end) {
  std::size_t off = 0;
  while (off < b.size()) {
    if (monotonic_ms() >= end)
      fail("TLS write timed out");
    int rc = SSL_write(
        ssl_, b.data() + off,
        static_cast<int>(std::min<std::size_t>(b.size() - off, 16384)));
    if (rc > 0) {
      off += rc;
      continue;
    }
    int e = SSL_get_error(ssl_, rc);
    if ((e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) ||
        !wait_fd(socket_, e == SSL_ERROR_WANT_WRITE, end))
      fail("TLS write failed");
  }
}
std::optional<Bytes> Tls::read(std::size_t limit, std::uint64_t end) {
  Bytes b(std::min<std::size_t>(limit, 16384));
  if (b.empty())
    fail("Invalid read bound");
  for (;;) {
    int rc = SSL_read(ssl_, b.data(), static_cast<int>(b.size()));
    if (rc > 0) {
      b.resize(rc);
      return b;
    }
    int e = SSL_get_error(ssl_, rc);
    if (e == SSL_ERROR_ZERO_RETURN)
      throw PeerClosed();
    if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
      fail("TLS read failed");
    if (!wait_fd(socket_, e == SSL_ERROR_WANT_WRITE, end))
      return std::nullopt;
  }
}
static HttpResponse parse_head(const std::string &h) {
  HttpResponse r;
  std::istringstream s(h);
  std::string version, line;
  s >> version >> r.status;
  std::getline(s, line);
  if (version != "HTTP/1.1" && version != "HTTP/1.0")
    fail("Invalid HTTP response");
  while (std::getline(s, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    auto i = line.find(':');
    if (i == std::string::npos)
      continue;
    auto value = line.substr(i + 1);
    while (!value.empty() && value.front() == ' ')
      value.erase(value.begin());
    r.headers[lowercase(line.substr(0, i))] = value;
  }
  return r;
}
HttpResponse https(const std::string &method, const std::string &url,
                   const std::string &body, const std::string &token,
                   const std::map<std::string, std::string> &verification_headers,
                   std::uint64_t timeout_ms, std::size_t response_limit) {
  if (!response_limit || response_limit > 16 * 1024 * 1024)
    fail("Invalid HTTP response limit");
  const auto started = monotonic_ms();
  const auto deadline = timeout_ms
      ? started + std::min(timeout_ms, std::numeric_limits<std::uint64_t>::max() - started)
      : 0;
  const std::size_t header_limit = 65536;
  // Bound encoded buffering as well as decoded body size. A separate 64 KiB
  // allowance covers chunk headers/trailers without letting tiny chunks grow
  // memory without limit. Neither allowance enlarges the accepted body.
  const auto buffered_limit = response_limit + header_limit + 65536;
  auto u = Url::parse(url);
  Tls t;
  t.connect(u, client_context(), deadline);
  std::string req =
      method + " " + u.path + " HTTP/1.1\r\nHost: " + u.host +
      "\r\nUser-Agent: PBS-Discord/0.1\r\nAccept: "
      "application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n";
  if (!token.empty()) {
    if (token.find_first_of("\r\n") != std::string::npos)
      fail("Invalid session token");
    req += "Authorization: " + token + "\r\n";
  }
  for (const auto &[name, value] : verification_headers) {
    if ((name != "X-Captcha-Key" && name != "X-Captcha-Rqtoken" &&
         name != "X-Captcha-Session-Id") || value.empty() || value.size() > 8192 ||
        std::any_of(value.begin(), value.end(), [](unsigned char c) {
          return c < 0x20 || c == 0x7f;
        }))
      fail("Invalid login verification header");
    req += name + ": " + value + "\r\n";
  }
  if (!body.empty())
    req += "Content-Type: application/json\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n";
  req += "\r\n" + body;
  if (deadline && monotonic_ms() >= deadline)
    fail("HTTP request timed out");
  t.write(req, deadline ? deadline : monotonic_ms() + 12000);
  std::string data;
  std::size_t head = std::string::npos;
  HttpResponse r;
  auto end = deadline ? deadline : monotonic_ms() + 20000;
  for (;;) {
    if (deadline && monotonic_ms() >= deadline)
      fail("HTTP response timed out");
    if (data.size() >= buffered_limit)
      fail("HTTP response too large");
    try {
      auto b = t.read(std::min<std::size_t>(16384, buffered_limit - data.size()), end);
      if (!b)
        fail("HTTP response timed out");
      data.append(reinterpret_cast<const char *>(b->data()), b->size());
      if (deadline && monotonic_ms() >= deadline)
        fail("HTTP response timed out");
    } catch (const PeerClosed &) {
      if (head != std::string::npos && !r.headers.contains("content-length") &&
          !r.headers.contains("transfer-encoding"))
        break;
      throw;
    }
    if (head == std::string::npos) {
      auto e = data.find("\r\n\r\n");
      if (e == std::string::npos) {
        if (data.size() > header_limit)
          fail("HTTP headers too large");
        continue;
      }
      head = e + 4;
      if (head > header_limit)
        fail("HTTP headers too large");
      r = parse_head(data.substr(0, e));
      if (r.status == 204)
        break;
    }
    if (r.headers.contains("content-length")) {
      std::size_t expected = std::stoull(r.headers.at("content-length"));
      if (expected > response_limit)
        fail("HTTP response too large");
      if (data.size() - head >= expected) {
        r.body = data.substr(head, expected);
        if (deadline && monotonic_ms() >= deadline)
          fail("HTTP response timed out");
        return r;
      }
    } else if (r.headers.contains("transfer-encoding") &&
               lowercase(r.headers.at("transfer-encoding")) == "chunked") {
      std::size_t at = head;
      std::string decoded;
      bool done = false;
      while (true) {
        if (deadline && monotonic_ms() >= deadline)
          fail("HTTP response timed out");
        auto e = data.find("\r\n", at);
        if (e == std::string::npos)
          break;
        auto line = data.substr(at, e - at);
        auto semi = line.find(';');
        line = line.substr(0, semi);
        if (line.empty() || line.find_first_not_of("0123456789abcdefABCDEF") !=
                                std::string::npos)
          fail("Invalid HTTP chunk");
        auto n = std::stoull(line, nullptr, 16);
        if (n > response_limit - decoded.size())
          fail("HTTP chunk too large");
        at = e + 2;
        if (!n) {
          if (data.size() >= at + 2) {
            done = true;
            break;
          }
          break;
        }
        if (data.size() < at + n + 2)
          break;
        if (data.substr(at + n, 2) != "\r\n")
          fail("Invalid HTTP chunk ending");
        decoded.append(data, at, n);
        at += n + 2;
      }
      if (done) {
        r.body = std::move(decoded);
        if (deadline && monotonic_ms() >= deadline)
          fail("HTTP response timed out");
        return r;
      }
    } else if (data.size() - head > response_limit)
      fail("HTTP response too large");
  }
  if (head != std::string::npos) {
    if (data.size() - head > response_limit)
      fail("HTTP response too large");
    r.body = data.substr(head);
  }
  if (deadline && monotonic_ms() >= deadline)
    fail("HTTP response timed out");
  return r;
}
void WebSocket::connect(const std::string &url, const std::string &origin,
                        std::size_t limit) {
  close();
  limit_ = limit;
  auto u = Url::parse(url);
  tls_.connect(u, client_context());
  std::string key = base64(random_bytes(16));
  std::string req =
      "GET " + u.path + " HTTP/1.1\r\nHost: " + u.authority() +
      "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " +
      key + "\r\nSec-WebSocket-Version: 13\r\nOrigin: " + origin +
      "\r\nUser-Agent: PBS-Discord/0.1\r\n\r\n";
  tls_.write(req, monotonic_ms() + 10000);
  std::string head;
  auto end = monotonic_ms() + 15000;
  while (head.find("\r\n\r\n") == std::string::npos) {
    auto b = tls_.read(16384, end);
    if (!b)
      fail("WebSocket upgrade timed out");
    head.append(reinterpret_cast<const char *>(b->data()), b->size());
    if (head.size() > 65536)
      fail("WebSocket upgrade too large");
  }
  auto at = head.find("\r\n\r\n") + 4;
  auto response = parse_head(head.substr(0, at));
  std::string proof = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char *>(proof.data()), proof.size(),
       digest);
  if (response.status != 101 ||
      lowercase(response.headers["upgrade"]) != "websocket" ||
      response.headers["sec-websocket-accept"] != base64(digest))
    fail("WebSocket upgrade rejected");
  buffered_.assign(head.begin() + at, head.end());
}
void WebSocket::send(std::uint8_t op, View data) {
  if (data.size() > limit_)
    fail("WebSocket message too large");
  Bytes out{static_cast<std::uint8_t>(0x80 | op)};
  if (data.size() < 126)
    out.push_back(0x80 | data.size());
  else if (data.size() <= 65535) {
    out.push_back(0x80 | 126);
    out.push_back(data.size() >> 8);
    out.push_back(data.size());
  } else {
    out.push_back(0x80 | 127);
    auto n = static_cast<std::uint64_t>(data.size());
    for (int i = 7; i >= 0; --i)
      out.push_back(n >> (8 * i));
  }
  auto mask = random_bytes(4);
  out.insert(out.end(), mask.begin(), mask.end());
  for (std::size_t i = 0; i < data.size(); ++i)
    out.push_back(data[i] ^ mask[i % 4]);
  tls_.write(out, monotonic_ms() + 5000);
}
void WebSocket::text(const std::string &s) {
  send(1, View(reinterpret_cast<const std::uint8_t *>(s.data()), s.size()));
}
void WebSocket::binary(View b) { send(2, b); }
void WebSocket::close() {
  if (tls_.fd() >= 0) {
    try {
      const std::uint8_t code[] = {3, 232};
      send(8, code);
    } catch (...) {
    }
  }
  tls_.close();
  buffered_.clear();
  message_.clear();
  fragmented_ = false;
}
WebSocketClose::WebSocketClose(std::optional<std::uint16_t> code,
                             const std::string &reason)
    : std::runtime_error("WebSocket session ended" +
                         (code ? " (code " + std::to_string(*code) +
                                     (reason.empty() ? "" : ": " + reason) + ")"
                               : " (no close code)")),
      code_(code), reason_(reason) {}
WebSocketClose WebSocketClose::from_payload(View payload) {
  if (payload.size() == 1 || payload.size() > 125)
    fail("Invalid WebSocket close payload");
  if (payload.empty())
    return WebSocketClose(std::nullopt, {});
  const auto code = static_cast<std::uint16_t>((payload[0] << 8) | payload[1]);
  std::string reason;
  reason.reserve(payload.size() - 2);
  for (std::size_t i = 2; i < payload.size(); ++i) {
    const auto c = payload[i];
    reason += c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '?';
  }
  return WebSocketClose(code, reason);
}
std::optional<WebSocket::Message> WebSocket::receive(std::uint64_t end) {
  for (;;) {
    if (buffered_.size() >= 2) {
      auto a = buffered_[0], b = buffered_[1];
      bool fin = a & 0x80;
      unsigned op = a & 15;
      if ((a & 0x70) || (b & 0x80))
        fail("Invalid WebSocket frame flags");
      std::uint64_t len = b & 127;
      std::size_t header = 2;
      if (len == 126) {
        if (buffered_.size() < 4)
          goto need_more;
        len = (buffered_[2] << 8) | buffered_[3];
        header = 4;
      } else if (len == 127) {
        if (buffered_.size() < 10)
          goto need_more;
        len = 0;
        for (int i = 2; i < 10; ++i)
          len = (len << 8) | buffered_[i];
        header = 10;
      }
      if (len > limit_ || message_.size() + len > limit_)
        fail("WebSocket frame limit exceeded");
      if (buffered_.size() < header + len)
        goto need_more;
      Bytes payload(buffered_.begin() + header,
                    buffered_.begin() + header + len);
      buffered_.erase(buffered_.begin(), buffered_.begin() + header + len);
      if (op >= 8) {
        if (!fin || len > 125)
          fail("Invalid WebSocket control frame");
        if (op == 8)
          throw WebSocketClose::from_payload(payload);
        if (op == 9)
          send(10, payload);
        else if (op != 10)
          fail("Unknown WebSocket opcode");
        continue;
      }
      if (op == 1 || op == 2) {
        if (fragmented_)
          fail("Unexpected WebSocket fragment");
        binary_ = op == 2;
      } else if (op != 0 || !fragmented_)
        fail("Unexpected WebSocket continuation");
      message_.insert(message_.end(), payload.begin(), payload.end());
      fragmented_ = !fin;
      if (fin) {
        Message m{binary_, std::move(message_)};
        message_.clear();
        return m;
      }
      continue;
    }
  need_more:
    auto next = tls_.read(16384, end);
    if (!next)
      return std::nullopt;
    buffered_.insert(buffered_.end(), next->begin(), next->end());
  }
}
Udp::~Udp() { close(); }
void Udp::close() {
  if (socket_ >= 0) {
    ::close(socket_);
    socket_ = -1;
  }
}
void Udp::connect(const std::string &ip, int port) {
  close();
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (port < 1 || port > 65535 ||
      inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
    fail("Invalid UDP endpoint");
  socket_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_ < 0 ||
      ::connect(socket_, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0)
    fail("UDP connection failed");
  nonblock(socket_);
}
void Udp::send(View b) {
  // A full socket buffer is local backpressure, not network loss. Dropping
  // here would break a video access unit for every receiver, so wait for
  // writability instead; the event loop's own deadlines bound any persistent
  // stall, and the pacing loop keeps bursts short.
  for (;;) {
    auto n = ::send(socket_, b.data(), b.size(), 0);
    if (n == static_cast<ssize_t>(b.size()))
      return;
    if (errno == EINTR)
      continue;
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      fail("UDP send failed");
    pollfd p{socket_, POLLOUT, 0};
    if (poll(&p, 1, 1000) <= 0)
      fail("UDP send stalled");
  }
}
std::optional<Bytes> Udp::receive() {
  if (socket_ < 0)
    return std::nullopt;
  Bytes b(4096);
  auto n = recv(socket_, b.data(), b.size(), 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      return std::nullopt;
    fail("UDP receive failed");
  }
  b.resize(n);
  return b;
}
} // namespace pbsd
