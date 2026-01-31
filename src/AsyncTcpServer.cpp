#include "AsyncTcpServer.hpp"
#include "ResolverCore.hpp"
#include "ResolverStructs.hpp"
#include "Message.hpp"
#include "types.hpp"
#include "util.hpp"
#include "config.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <array>
#include <vector>

#ifndef DISABLE_STATISTICS
#include "metrics.hpp"
#endif

namespace net = boost::asio;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

AsyncTcpServer::AsyncTcpServer(ResolverCore& core) : resolver{core} {}

awaitable<void>
AsyncTcpServer::listen(u16 port) {
    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor{executor, {tcp::v4(), port}};

    while (true) {
        tcp::socket sock = co_await acceptor.async_accept(use_awaitable);
        net::co_spawn(
            executor,
            handle_cli(std::move(sock)),
            net::detached
        );
    }
}


awaitable<void>
AsyncTcpServer::send_dns_bytes(
    tcp::socket& sock,
    const std::vector<u8>& bytes
) {
    size_t sz = bytes.size();
    std::array<u8, 2> dns_len_buf = {
        static_cast<u8>(sz >> 8), static_cast<u8>(sz & 0xFF)
    };
    co_await net::async_write(
        sock, net::buffer(dns_len_buf), use_awaitable
    );
    co_await net::async_write(
        sock, net::buffer(bytes), use_awaitable
    );
}

awaitable<size_t>
AsyncTcpServer::rcv_dns_bytes(
    tcp::socket& sock,
    std::vector<u8>& buf
) {
    std::array<u8, 2> dns_len_buf;
    co_await net::async_read(sock, net::buffer(dns_len_buf), use_awaitable);
    size_t len = (dns_len_buf[0] << 8) | dns_len_buf[1];
    buf.resize(len);
    co_await net::async_read(sock, net::buffer(buf), use_awaitable);
    co_return len;
}


awaitable<void>
AsyncTcpServer::handle_cli(tcp::socket sock) {
    #ifndef DISABLE_STATISTICS
    ScopedMeasure measure{Metric::cli_resolve_total_tcp};
    #endif
    
    try {
        while (true) {
            std::vector<u8> cli_query_bytes(4096);
            co_await rcv_dns_bytes(sock, cli_query_bytes);
        
            if (cli_query_bytes.size() < Header::HEADER_SZ)
                co_return;
        
            auto cli_query_msg = Message::deserialize(cli_query_bytes);
            if (!cli_query_msg) {
                Message::make_formerr(cli_query_bytes);
                co_await send_dns_bytes(sock, cli_query_bytes);
                co_return;
            }
        
            if (cli_query_msg->questions.size() == 0)
                co_return;
            if (!cli_query_msg->header.is_rd()) {
                Message::make_servfail(cli_query_bytes);
                co_await send_dns_bytes(sock, cli_query_bytes);
                co_return;
            }
        
            ResolverResult res = co_await resolver.resolve(cli_query_msg->questions.front());
            if (res.status != ResolverStatus::Success) {
                Message::make_servfail(cli_query_bytes);
                co_await send_dns_bytes(sock, cli_query_bytes);
                co_return;
            }
        
            ClientContext cli_ctx{
                .id = cli_query_msg->header.id,
                .cli_q = cli_query_msg->questions.front()
            };
            cli_query_msg->assign_edns_related_fields(cli_ctx);
        
            Message::finalize_response(res, cli_ctx);
            auto response_bytes = res.msg.serialize();
        
            if (!response_bytes)
                co_return;
        
            co_await send_dns_bytes(sock, *response_bytes);

            LOG("response sent\n");
        }
    } catch (const boost::system::system_error& e) {
        co_return;
    }
}
