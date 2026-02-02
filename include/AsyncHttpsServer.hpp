#pragma once

#include "types.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <vector>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = net::ssl;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

class ResolverCore;

class AsyncHttpsServer {
private:
    ResolverCore& resolver;

public:
    AsyncHttpsServer(ResolverCore& core);

    awaitable<void>
    listen(const u16 port);
    
private:
    awaitable<void>
    handle_cli(ssl::stream<tcp::socket> stream);

    static http::response<http::vector_body<u8>>
    prepare_http_response(std::vector<u8>&& bytes);
};
