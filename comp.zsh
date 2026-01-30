#!/bin/zsh
clang++ src/*.cpp -I include -I /opt/homebrew/opt/boost/include -Wall -std=c++20 -o main_asio