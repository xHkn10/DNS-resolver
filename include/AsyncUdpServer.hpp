#pragma once

#include "types.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

class ResolverCore;

namespace net = boost::asio;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;

class AsyncUdpServer {
    ResolverCore& resolver;

public:
    AsyncUdpServer(ResolverCore& core);

    awaitable<void>
    listen(u16 port);

private:
    awaitable<void>
    handle_cli(
        std::vector<u8> cli_query_bytes,
        udp::endpoint cli,
        udp::socket& sock
    );
};
