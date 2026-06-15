cmake_minimum_required(VERSION 3.30)
project(DNS CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(DNS
        src/AsyncHttpsServer.cpp
        src/AsyncTcpServer.cpp
        src/AsyncTlsServer.cpp
        src/AsyncUdpServer.cpp
        src/Cache.cpp
        src/main.cpp
        src/Message.cpp
        src/ResolverCore.cpp
        src/SyncUdpResolver.cpp
)

target_include_directories(DNS PRIVATE include)

target_link_libraries(DNS PRIVATE
        Boost::boost
        OpenSSL::SSL
)
