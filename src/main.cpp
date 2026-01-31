#include "AsyncTcpServer.hpp"
#include "AsyncUdpServer.hpp"
#include "ResolverCore.hpp"
#include "config.hpp"
// #include "SyncUdpResolver.hpp"

#include <iostream>
#include <netinet/in.h>

int main() {
    net::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& e, int sig) {
        if (!e)
            io.stop();
    });

    ResolverCore core{};
    AsyncUdpServer udp_r{core};
    AsyncTcpServer tcp_r{core};
    
    net::co_spawn(io, udp_r.listen(PORT), net::detached);
    net::co_spawn(io, tcp_r.listen(PORT), net::detached);
    std::cout << "Listening on port " << PORT << std::endl;
    io.run();
}
