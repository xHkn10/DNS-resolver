#!/bin/zsh

clang++ -std=c++20 -O3 -Wall \
    src/*.cpp \
    -I include \
    -I /opt/homebrew/include \
    -L /opt/homebrew/lib \
    -lssl \
    -lcrypto \
    -o dns_server
