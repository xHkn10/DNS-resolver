#include "AsyncTcpServer.hpp"
#include "AsyncTlsServer.hpp"
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
    AsyncUdpServer udp{core};
    AsyncTcpServer tcp{core};
    AsyncTlsServer tls{core};
    
    net::co_spawn(io, udp.listen(UDP_PORT), net::detached);
    net::co_spawn(io, tcp.listen(TCP_PORT), net::detached);
    net::co_spawn(io, tls.listen(TLS_PORT), net::detached);

    std::cout << "Listening...\n";

    io.run();
}
