# Async Recursive DNS resolver

### Features
Async IO with Boost Asio coroutines
DNS message parsing and serialization
Recursive Resolution (root -> TLD -> authoritative)
Client can query with DNS over UDP, over TCP or with TLS. (DoH in development)
Server uses DNS over UDP to query nameservers, fallback to TCP if truncated

### Build
Requirements:
C++20
Boost
OpenSSL

Compile with ./comp.zsh
Stress test with ./dig_test.zsh