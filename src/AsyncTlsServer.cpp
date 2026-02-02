#include "AsyncTlsServer.hpp"
#include "Message.hpp"
#include "ResolverCore.hpp"
#include "ResolverStructs.hpp"
#include "types.hpp"
#include "util.hpp"
#include <vector>

namespace net = boost::asio;
namespace ssl = net::ssl;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

AsyncTlsServer::AsyncTlsServer(ResolverCore& core) : resolver{core} {
    ctx_.use_certificate_chain_file("server.crt");
    ctx_.use_private_key_file("server.key", ssl::context::pem);
}

awaitable<void>
AsyncTlsServer::listen(const u16 port) {
    auto executor = co_await net::this_coro::executor;

    tcp::acceptor acceptor{executor, {tcp::v4(), port}};

    while (true) {
        tcp::socket sock = co_await acceptor.async_accept(use_awaitable);
        ssl::stream<tcp::socket> ssl_stream{std::move(sock), ctx_};

        net::co_spawn(
            executor,
            handle_cli(std::move(ssl_stream)),
            net::detached
        );
    }
}

awaitable<void>
AsyncTlsServer::handle_cli(ssl::stream<tcp::socket> ssl_stream) {

    {
        boost::system::error_code ec;
        co_await ssl_stream.async_handshake(
            ssl::stream_base::server, 
            net::redirect_error(use_awaitable, ec)
        );
        if (ec)
            co_return;
    }

    std::vector<u8> cli_query_bytes(4096);

    co_await rcv_dns_bytes(ssl_stream, cli_query_bytes);

    if (cli_query_bytes.size() < Header::HEADER_SZ)
        goto shutdown;

    {
        auto cli_query_msg = Message::deserialize(cli_query_bytes);
        if (!cli_query_msg) {
            Message::make_formerr(cli_query_bytes);
            co_await send_dns_bytes(ssl_stream, cli_query_bytes);
            goto shutdown;
        }
        if (cli_query_msg->questions.size() == 0)
            goto shutdown;
        if (!cli_query_msg->header.is_rd()) {
            Message::make_servfail(cli_query_bytes);
            co_await send_dns_bytes(ssl_stream, cli_query_bytes);
            goto shutdown;
        }

        ResolverResult res = co_await resolver.resolve(cli_query_msg->questions.front());
        if (res.status != ResolverStatus::Success) {
            Message::make_servfail(cli_query_bytes);
            co_await send_dns_bytes(ssl_stream, cli_query_bytes);
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

        co_await send_dns_bytes(ssl_stream, *response_bytes);
    }

    shutdown:
    {
        boost::system::error_code ec;
        co_await ssl_stream.async_shutdown(net::redirect_error(use_awaitable, ec));
        ec = ssl_stream.lowest_layer().shutdown(tcp::socket::shutdown_send, ec);
        ssl_stream.lowest_layer().close();
    }

    LOG("Connection shutdown\n");
}

awaitable<void>
AsyncTlsServer::send_dns_bytes(
    ssl::stream<tcp::socket>& ssl_stream,
    const std::vector<u8>& bytes
) {
    u16 len = htons(bytes.size());
    boost::system::error_code ec;

    co_await net::async_write(
        ssl_stream, net::buffer(&len, 2),
        net::redirect_error(use_awaitable, ec)
    );
    co_await net::async_write(
        ssl_stream, net::buffer(bytes),
        net::redirect_error(use_awaitable, ec)
    );
}
    
awaitable<size_t>
AsyncTlsServer::rcv_dns_bytes(
    ssl::stream<tcp::socket>& ssl_stream,
    std::vector<u8>& buf
) {

    u16 len;
    {
        boost::system::error_code ec;
        co_await net::async_read(
            ssl_stream, net::buffer(&len, 2),
            net::redirect_error(use_awaitable, ec)
        );
        ntohs(len);
        if (ec)
            co_return 0;
    }

    buf.resize(len);
    
    {
        boost::system::error_code ec;
        co_await net::async_read(
            ssl_stream, net::buffer(buf),
            net::redirect_error(use_awaitable, ec)
        );
        if (ec)
            co_return 0;
    }

    co_return len;
}