# Async Recursive DNS Resolver

## Features
- Async I/O with Boost.Asio coroutines
- DNS message parsing and serialization
- Recursive resolution (root → TLD → authoritative)
- Client queries supported over:
  - DNS over UDP
  - DNS over TCP
  - DNS over TLS  
  - DoH in development
- Server queries nameservers using DNS over UDP, with TCP fallback on truncation

## Build

### Requirements
- C++20
- Boost
- OpenSSL

### Compile
- ./comp.zsh

### Generate Certificate And Private Key
- ./create_crt_key.zsh

### Stress test
- ./dig_test.zsh