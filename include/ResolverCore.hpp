#pragma once

#include "Cache.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

struct Question;
struct ResolverResult;

namespace net = boost::asio;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

class ResolverCore {
private:
    Cache cache;

public:
    ResolverCore() = default;

    awaitable<ResolverResult>
    resolve(const Question& q);

    awaitable<ResolverResult>
    resolve(const Question& q, int& n_it);

    awaitable<size_t>
    query_in_udp(
        const ResourceRecord& rr,
        const std::vector<u8>& query_bytes, 
        std::vector<u8>& buf
    );

    awaitable<size_t>
    query_in_tcp(
        const ResourceRecord& rr,
        const std::vector<u8>& query_bytes, 
        std::vector<u8>& buf
    );

    std::optional<Message>
    parse_and_validate_response(
        std::vector<u8>& response,
        u16 id
    );
};
