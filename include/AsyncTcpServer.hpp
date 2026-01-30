#pragma once

#include "types.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

namespace net = boost::asio;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

class ResolverCore;

class AsyncTcpServer {
private:
    ResolverCore& resolver;

public:
    AsyncTcpServer(ResolverCore& core);

    awaitable<void>
    listen(const u16 port);

    static awaitable<void>
    send_dns_bytes(tcp::socket& sock, const std::vector<u8>& bytes);
    
    static awaitable<size_t>
    rcv_dns_bytes(tcp::socket& sock, std::vector<u8>& buf);
    
private:
    awaitable<void>
    handle_cli(tcp::socket sock);
};
