#include "AsyncHttpsServer.hpp"
#include "ResolverCore.hpp"
#include "Message.hpp"
#include "ResolverStructs.hpp"
#include "types.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <vector>

#ifndef DISABLE_STATISTICS
#include "metrics.hpp"
#endif

#define DISABLE_STATISTICS

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = net::ssl;
using net::ip::tcp;
using net::awaitable;
using net::use_awaitable;

AsyncHttpsServer::AsyncHttpsServer(ResolverCore& core) : resolver{core} {}

awaitable<void>
AsyncHttpsServer::listen(const u16 port) {
    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor{executor, {tcp::v4(), port}};

    ssl::context ctx{ssl::context::tlsv12_server};
    ctx.use_certificate_chain_file("server.crt");
    ctx.use_private_key_file("server.key", ssl::context::pem);

    SSL_CTX* ssl_ctx = ctx.native_handle();

    SSL_CTX_set_alpn_select_cb(ssl_ctx, [](SSL* ssl, const unsigned char** out, 
                                        unsigned char* outlen, const unsigned char* in, 
                                        unsigned int inlen, void* arg) -> int {
        unsigned char next_proto[] = "\x02h2\x08http/1.1";
        
        if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, 
                                next_proto, sizeof(next_proto) - 1, 
                                in, inlen) != OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    }, nullptr);

    while (true) {
        tcp::endpoint cli;

        tcp::socket sock = co_await acceptor.async_accept(use_awaitable);
        ssl::stream<tcp::socket> stream{std::move(sock), ctx};

        net::co_spawn(
            executor,
            handle_cli(std::move(stream)),
            net::detached
        );
    }
}

awaitable<void>
AsyncHttpsServer::handle_cli(ssl::stream<tcp::socket> ssl_stream) {
    #ifndef DISABLE_STATISTICS
    ScopedMeasure measure{Metric::cli_resolve_total_https};
    #endif
    
    co_await ssl_stream.async_handshake(
        ssl::stream_base::server, use_awaitable
    );
    beast::flat_buffer buffer(4096);

    http::request<http::vector_body<u8>> req;
    co_await http::async_read(
        ssl_stream, buffer, req, use_awaitable
    );

    if (buffer.size() < Header::HEADER_SZ)
        goto shutdown;

    {
        auto cli_query_msg = Message::deserialize(req.body());
        if (!cli_query_msg) {
            Message::make_formerr(req.body());
            goto send_response;
        }
        if (cli_query_msg->questions.size() == 0)
            goto shutdown;
        if (!cli_query_msg->header.is_rd()) {
            Message::make_servfail(req.body());
            goto send_response;
        }

        ResolverResult res = co_await resolver.resolve(cli_query_msg->questions.front());
        if (res.status != ResolverStatus::Success) {
            Message::make_servfail(req.body());
            goto send_response;
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

        http::response<http::vector_body<u8>>
        response = AsyncHttpsServer::prepare_http_response(std::move(req.body()));
        co_await http::async_write(
                ssl_stream, response, use_awaitable
            );
    }

    send_response:
    {
        http::response<http::vector_body<u8>>
        response = AsyncHttpsServer::prepare_http_response(std::move(req.body()));
        co_await http::async_write(
            ssl_stream, response, use_awaitable
        );
    }

    shutdown:
    boost::system::error_code ec;
    co_await ssl_stream.async_shutdown(net::redirect_error(use_awaitable, ec));
    ec = ssl_stream.lowest_layer().shutdown(tcp::socket::shutdown_send, ec);
    ssl_stream.lowest_layer().close();
    
    LOG("Connection shutdown\n");
}


http::response<http::vector_body<u8>>
AsyncHttpsServer::prepare_http_response(std::vector<u8>&& bytes) {
    http::response<http::vector_body<u8>> response{http::status::ok, 443};
    response.set(http::field::server, "0xhkn dns");
    response.set(http::field::content_type, "text/plain");
    response.body() = std::move(bytes);
    response.prepare_payload();
    return response;
}