# PS5 Game Activity

Load `ps5-game-activity.elf` with your PS5 payload loader. On a device on the same trusted LAN, open `http://<PS5 IP>:9876/` using the console's numeric IPv4 address. Select **Sign in with Discord**, scan the QR code in the Discord mobile app, and approve the login on your phone. If Discord requests verification, complete it on the dashboard.

After Discord accepts the login, the payload automatically saves it and restores it on the next launch. Game activity updates while the payload is running, even with the page closed. The website uses plain HTTP on the local network. The dashboard has no separate login, so keep its port on your trusted LAN.

Select **Sign out and delete all credentials**, then confirm, to clear the payload's active session and delete its saved vault and key. The standalone payload uses `/data/ps5-game-activity` for its files.

## Build from source
Use a PS5 payload SDK and a static PS5 dependency prefix containing OpenSSL 3, libsodium and nlohmann/json 3.11 or newer. The compiler wrappers use clang and lld.

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/ps5.cmake -DPS5_DEPS_PREFIX=/path/to/ps5-deps
cmake --build build
```

For a host build, omit the toolchain and dependency prefix arguments and install host OpenSSL and nlohmann/json development packages. For optional offline artwork, run the artwork cache script with `--output-dir /data/ps5-game-activity`.

See [LICENSE](LICENSE) and the included notices for OpenSSL, libsodium, the CA bundle and the QR generator.
