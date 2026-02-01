#include "AsyncUdpServer.hpp"
#include "ResolverCore.hpp"
#include "Message.hpp"
#include "ResolverStructs.hpp"
#include "types.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>

#ifndef DISABLE_STATISTICS
#include "metrics.hpp"
#endif

#define DISABLE_STATISTICS

namespace net = boost::asio;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;

AsyncUdpServer::AsyncUdpServer(ResolverCore& core) : resolver{core} {}

awaitable<void>
AsyncUdpServer::listen(const u16 port) {
    auto executor = co_await net::this_coro::executor;
    udp::socket listen_sock{executor, udp::endpoint{udp::v4(), port}};

    while (true) {
        std::vector<u8> buffer(4096);
        udp::endpoint cli;

        size_t n = co_await listen_sock.async_receive_from(
            net::buffer(buffer), cli, use_awaitable
        );
        buffer.resize(n);

        net::co_spawn(
            executor,
            handle_cli(std::move(buffer), cli, listen_sock),
            net::detached
        );
    }
}

awaitable<void>
AsyncUdpServer::handle_cli(
    std::vector<u8> cli_query_bytes,
    udp::endpoint cli,
    udp::socket& sock
) {

    #ifndef DISABLE_STATISTICS
    ScopedMeasure measure{Metric::cli_resolve_total_udp};
    #endif

    if (cli_query_bytes.size() < Header::HEADER_SZ)
        co_return;

    auto cli_query_msg = Message::deserialize(cli_query_bytes);
    if (!cli_query_msg) {
        Message::make_formerr(cli_query_bytes);
        co_await sock.async_send_to(
            net::buffer(cli_query_bytes), cli, use_awaitable
        );
        co_return;
    }

    if (cli_query_msg->questions.size() == 0)
        co_return;
    if (!cli_query_msg->header.is_rd()) {
        Message::make_servfail(cli_query_bytes);
        co_return;
    }

    ResolverResult res = co_await resolver.resolve(cli_query_msg->questions.front());
    if (res.status != ResolverStatus::Success) {
        Message::make_servfail(cli_query_bytes);
        co_return;
    }

    ClientContext cli_ctx{
        .cli_q = cli_query_msg->questions.front(),
        .id = cli_query_msg->header.id,
        .mode = DnsMode::UDP
    };
    cli_query_msg->assign_edns_related_fields(cli_ctx);

    Message::finalize_response(res, cli_ctx);
    auto response_bytes = res.msg.serialize();

    if (!response_bytes)
        co_return;

    co_await sock.async_send_to(
        net::buffer(*response_bytes),
        cli,
        use_awaitable
    );

    LOG("Response sent\n");
}
