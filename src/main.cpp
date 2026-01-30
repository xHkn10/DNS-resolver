//#include "SyncUdpResolver.hpp"
#include "AsyncUdpResolver.hpp"
#include <exception>
#include <iostream>
#include <netinet/in.h>

int main() {
    // SyncUdpResolver r;
    // r.init();
    // std::cout << "Server initialized" << std::endl;
    // std::cout << "Listening..." << std::endl;
    // r.listen();

    const int port = 3169;

    try {
        net::io_context io;
        AsyncUdpResolver r{};
        net::co_spawn(io, r.listen(port), net::detached);

        std::cout << "Listening on port " << port << std::endl;

        io.run();

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}