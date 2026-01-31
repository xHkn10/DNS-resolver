#!/bin/zsh
clang++ src/*.cpp -I include -I bench -I /opt/homebrew/opt/boost/include -Wall -std=c++20 -o sync_udp_dns_server -O3
