#pragma once

#include "types.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

namespace net = boost::asio;
namespace ssl = net::ssl;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

class ResolverCore;

class AsyncTlsServer {
private:
    ResolverCore& resolver;
    ssl::context ctx_{ssl::context::tlsv12_server};

public:
    AsyncTlsServer(ResolverCore& core);

    awaitable<void>
    listen(const u16 port);
    
private:
    awaitable<void>
    handle_cli(ssl::stream<tcp::socket> ssl_stream);

    static awaitable<void>
    send_dns_bytes(
        ssl::stream<tcp::socket>& ssl_stream,
        const std::vector<u8>& bytes
    );
    
    static awaitable<size_t>
    rcv_dns_bytes(
        ssl::stream<tcp::socket>& ssl_stream,
        std::vector<u8>& buf
    );
};
