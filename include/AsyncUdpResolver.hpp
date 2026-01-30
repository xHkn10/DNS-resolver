#pragma once

#include "ResolverStructs.hpp"
#include "Cache.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

namespace net = boost::asio;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;

class AsyncUdpResolver {
private:
    Cache cache;

public:
    AsyncUdpResolver();

    awaitable<void>
    listen(const u16 port);

private:
    awaitable<void>
    handle_cli_query(
        std::vector<u8> cli_query_bytes,
        udp::endpoint cli,
        udp::socket& sock
    );

    void
    finalize_response(ResolverResult& res, const ClientContext& cli);

    awaitable<void>
    send_servfail(
        std::vector<u8>& cli_query_bytes,
        udp::endpoint cli,
        udp::socket& sock
    );

    awaitable<void>
    send_formerr(
        std::vector<u8>& cli_query_bytes,
        udp::endpoint cli, udp::socket& sock
    );

    awaitable<ResolverResult>
    resolve(const Question& q);

    awaitable<ResolverResult>
    resolve(const Question& q, int& n_it);
};
