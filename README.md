# Async Recursive DNS resolver

### Features
Async IO with Boost Asio coroutines \n
DNS message parsing and serialization \n
Recursive Resolution (root -> TLD -> authoritative) \n
Client can query with DNS over UDP, over TCP or with TLS. (DoH in development) \n
Server uses DNS over UDP to query nameservers, fallback to TCP if truncated \n

### Build
Requirements: \n
C++20 \n
Boost \n
OpenSSL \n

Compile with ./comp.zsh \n
Stress test with ./dig_test.zsh \n