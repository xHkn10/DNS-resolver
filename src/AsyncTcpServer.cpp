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
#include <sys/socket.h>
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
        boost::system::error_code ec;
        
        tcp::socket sock = co_await acceptor.async_accept(
            net::redirect_error(use_awaitable, ec)
        );
        if (ec)
            continue;

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

    boost::system::error_code ec;

    co_await net::async_write(
        sock, net::buffer(dns_len_buf),
        net::redirect_error(use_awaitable, ec)
    );
    co_await net::async_write(
        sock, net::buffer(bytes),
        net::redirect_error(use_awaitable, ec)
    );
}

awaitable<size_t>
AsyncTcpServer::rcv_dns_bytes(
    tcp::socket& sock,
    std::vector<u8>& buf
) {

    std::array<u8, 2> dns_len_buf;

    {
        boost::system::error_code ec;
        co_await net::async_read(
            sock, net::buffer(dns_len_buf),
            net::redirect_error(use_awaitable, ec)
        );
        if (ec)
            co_return 0;
    }

    size_t len = (dns_len_buf[0] << 8) | dns_len_buf[1];
    buf.resize(len);
    
    {
        boost::system::error_code ec;
        co_await net::async_read(
            sock, net::buffer(buf),
            net::redirect_error(use_awaitable, ec)
        );
        if (ec)
            co_return 0;
    }

    co_return len;
}


awaitable<void>
AsyncTcpServer::handle_cli(tcp::socket sock) {
    #ifndef DISABLE_STATISTICS
    ScopedMeasure measure{Metric::cli_resolve_total_tcp};
    #endif
    
    std::vector<u8> cli_query_bytes(4096);
    co_await rcv_dns_bytes(sock, cli_query_bytes);

    if (cli_query_bytes.size() < Header::HEADER_SZ)
        goto shutdown;

    {
        auto cli_query_msg = Message::deserialize(cli_query_bytes);
        if (!cli_query_msg) {
            Message::make_formerr(cli_query_bytes);
            co_await send_dns_bytes(sock, cli_query_bytes);
            goto shutdown;
        }
        if (cli_query_msg->questions.size() == 0)
            goto shutdown;
        if (!cli_query_msg->header.is_rd()) {
            Message::make_servfail(cli_query_bytes);
            co_await send_dns_bytes(sock, cli_query_bytes);
            goto shutdown;
        }

        ResolverResult res = co_await resolver.resolve(cli_query_msg->questions.front());
        if (res.status != ResolverStatus::Success) {
            Message::make_servfail(cli_query_bytes);
            co_await send_dns_bytes(sock, cli_query_bytes);
            goto shutdown;
        }

        ClientContext cli_ctx{
            .cli_q = cli_query_msg->questions.front(),
            .id = cli_query_msg->header.id,
            .mode = DnsMode::TCP
        };
        cli_query_msg->assign_edns_related_fields(cli_ctx);

        Message::finalize_response(res, cli_ctx);
        auto response_bytes = res.msg.serialize();

        if (!response_bytes)
            goto shutdown;

        co_await send_dns_bytes(sock, *response_bytes);
    }

    shutdown:
    boost::system::error_code ec;
    ec = sock.shutdown(tcp::socket::shutdown_send, ec);
    sock.close();

    LOG("Connection shutdown\n");
}
