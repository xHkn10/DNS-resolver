//#include "SyncUdpResolver.hpp"
#include "AsyncTcpServer.hpp"
#include "AsyncUdpServer.hpp"
#include "ResolverCore.hpp"
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

        ResolverCore core{};
        AsyncUdpServer udp_r{core};
        AsyncTcpServer tcp_r{core};
        
        net::co_spawn(io, udp_r.listen(port), net::detached);
        net::co_spawn(io, tcp_r.listen(port), net::detached);

        std::cout << "Listening on port " << port << std::endl;

        io.run();

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}