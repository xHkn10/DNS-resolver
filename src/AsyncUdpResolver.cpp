#include "AsyncUdpResolver.hpp"
#include "Message.hpp"
#include "types.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <vector>

namespace net = boost::asio;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;

AsyncUdpResolver::AsyncUdpResolver() : cache{} {}

awaitable<void>
AsyncUdpResolver::listen(const u16 port) {
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
            handle_cli_query(std::move(buffer), cli, listen_sock),
            net::detached
        );
    }
}

awaitable<void>
AsyncUdpResolver::handle_cli_query(
    std::vector<u8> cli_query_bytes,
    udp::endpoint cli,
    udp::socket& sock
) {
    auto executor = co_await net::this_coro::executor;
    if (cli_query_bytes.size() < Header::HEADER_SZ)
        co_return;

    auto cli_query_msg = Message::deserialize(cli_query_bytes);
    if (!cli_query_msg) {
        co_await send_formerr(cli_query_bytes, cli, sock);
        co_return;
    }

    if (cli_query_msg->questions.size() == 0)
        co_return;
    if (!cli_query_msg->header.is_rd()) {
        co_await send_servfail(cli_query_bytes, cli, sock);
        co_return;
    }

    ResolverResult res = co_await resolve(cli_query_msg->questions.front());
    if (res.status != ResolverStatus::Success) {
        co_await send_servfail(cli_query_bytes, cli, sock);
        co_return;
    }

    ClientContext cli_ctx{
        .id = cli_query_msg->header.id
    };
    cli_query_msg->assign_edns_related_fields(cli_ctx);

    finalize_response(res, cli_ctx);
    auto response_bytes = res.msg.serialize();

    if (!response_bytes)
        co_return;

    co_await sock.async_send_to(
        net::buffer(*response_bytes),
        cli,
        use_awaitable
    );
    std::cout << "Response sent\n";
}

void
AsyncUdpResolver::finalize_response(
    ResolverResult& res,
    const ClientContext& cli
) {
    res.msg.header.id = cli.id;
    res.msg.header.set_qr_bit();
    res.msg.header.set_rd_bit();
    res.msg.header.set_ra_bit();
    res.msg.header.clear_aa_bit();
    res.msg.header.set_errcode(res.code);
    if (res.status == ResolverStatus::Success) {
        if (res.msg.header.ancount > 0)
            res.msg.strip_sections();
        else {
            res.msg.additional.clear();
            res.msg.header.arcount = 0;
        }
        if (cli.uses_edns)
            res.msg.put_edns_opt();
    }
    if (res.msg.size() > cli.max_payload)
        res.msg.truncate_msg(cli.max_payload);
}

awaitable<void>
AsyncUdpResolver::send_servfail(
    std::vector<u8>& cli_query_bytes,
    udp::endpoint cli,
    udp::socket& sock
) {
    memset(cli_query_bytes.data() + 2, 0, (cli_query_bytes.size() - 2) * sizeof(u8));
    cli_query_bytes[2] |= 0x80; // qr bit set
    cli_query_bytes[3] |= 0x80; // ra bit set
    cli_query_bytes[3] |= static_cast<u8>(RCode::ServFail);
    co_await sock.async_send_to(
        net::buffer(cli_query_bytes), cli, use_awaitable
    );
}

awaitable<void>
AsyncUdpResolver::send_formerr(
    std::vector<u8>& cli_query_bytes,
    udp::endpoint cli,
    udp::socket& sock
) {
    auto executor = co_await net::this_coro::executor;
    std::cerr << "Malformed DNS packet from client\n";
    memset(cli_query_bytes.data() + 2, 0, (cli_query_bytes.size() - 2) * sizeof(u8));
    cli_query_bytes[2] |= 0x80; // qr bit set
    cli_query_bytes[3] |= 0x80; // ra bit set
    cli_query_bytes[3] |= static_cast<u8>(RCode::FormErr);
    cli_query_bytes.resize(Header::HEADER_SZ);
    co_await sock.async_send_to(
        net::buffer(cli_query_bytes), cli, use_awaitable
    );
}

awaitable<ResolverResult>
AsyncUdpResolver::resolve(
    const Question& q
) {
    if (q.type == QType::ANY)
        co_return ResolverResult{ResolverStatus::Success, RCode::NotImp};
    
    Question active_query = q;
    std::vector<ResourceRecord> chain;
    
    {
        int limit = 8; // follow cname chain
        while (true) {
            if (--limit < 0)
                break;
            auto entry = cache.get(active_query.qname, q.type, q.klass);
            if (entry)
                co_return ResolverResult{
                    ResolverStatus::Success,
                    entry->code,
                    Message::from_cache_entry(chain, *entry, q)
                };

            auto cname = cache.get(active_query.qname, RRType::CNAME, DNSClass::IN);
            if (cname && !cname->rrset.empty()) {
                active_query = {cname->rrset.front().rdata, q.type, q.klass};
                chain.push_back(cname->rrset.front());
            } else
                break;
        }
    }
    
    int max_it = 30;
    while (true) {
        if (max_it < 0)
            break;

        ResolverResult res = co_await resolve(active_query, max_it);
        if (res.status != ResolverStatus::Success)
            co_return res;

        for (const ResourceRecord& rr : res.msg.answers) {
            if (rr.type == static_cast<RRType>(q.type)) {
                res.msg.answers.insert(res.msg.answers.begin(), chain.begin(), chain.end());
                res.msg.header.ancount = res.msg.answers.size();
                res.msg.questions.resize(1);
                res.msg.questions.front() = q;
                res.msg.header.qdcount = 1;
                co_return res;
            }
        }

        bool has_cname = false;
        for (const ResourceRecord& rr : res.msg.answers) {
            if (rr.type == RRType::CNAME) {
                chain.push_back(rr);
                active_query.qname = rr.rdata;
                has_cname = true;
                break;
            }
        }

        if (!has_cname)
            co_return res;
    }

    co_return ResolverResult{ResolverStatus::LoopDetected, RCode::ServFail};
}

awaitable<ResolverResult>
AsyncUdpResolver::resolve(
    const Question& q,
    int& n_it
) {
    auto executor = co_await net::this_coro::executor;
    
    Message query_msg = Message::from_question(q);
    auto query_bytes = query_msg.serialize();
    if (!query_bytes)
        co_return ResolverResult{ResolverStatus::InternalError, RCode::ServFail};

    while (true) {
        if (--n_it < 0)
            break;

        CacheEntry best_nss = cache.find_best_ns_rrset(q.qname);
        std::cout << "BEST NSS:\n" << util::dn_to_str(best_nss.rrset.front().rdata) << std::endl;
        util::shuffle(best_nss.rrset);

        std::vector<ResourceRecord> a_records;
        for (const ResourceRecord& ns : best_nss.rrset) {
            auto entry = cache.get(ns.rdata, RRType::A, DNSClass::IN);
            if (entry)
                a_records.insert(a_records.end(), entry->rrset.begin(), entry->rrset.end());
        }
        util::shuffle(a_records);

        for (const ResourceRecord& rr : a_records) {
            auto addr = net::ip::make_address_v4(
                *reinterpret_cast<const std::array<unsigned char, 4>*>(rr.rdata.data())
            );
            udp::endpoint target_endpoint{addr, 53};
            udp::socket sock{executor, udp::v4()};
            
            std::cout << "Queried " << util::dn_to_str(rr.name) << std::endl;
            co_await sock.async_send_to(
                net::buffer(*query_bytes), target_endpoint, use_awaitable
            );
            
            std::vector<u8> buffer(4096);
            udp::endpoint sender;
            size_t n = co_await sock.async_receive_from(
                net::buffer(buffer), sender, use_awaitable
            );
            buffer.resize(n);

            std::cout << "Received " << n << " bytes from " << util::dn_to_str(rr.name) << std::endl;

            if (n < Header::HEADER_SZ)
                continue;
            auto rcvd_msg = Message::deserialize(buffer);
            if (!rcvd_msg)
                continue;
            if (rcvd_msg->header.id != query_msg.header.id)
                continue;
            RCode rcvd_msg_code = rcvd_msg->header.get_err_code();
            if (rcvd_msg_code != RCode::NoError && rcvd_msg_code != RCode::NXDomain)
                continue;
            
            cache.cache_msg(*rcvd_msg);
            if (rcvd_msg->header.is_authoritative())
                co_return ResolverResult{
                    ResolverStatus::Success, rcvd_msg_code, *rcvd_msg
                };

            if (!rcvd_msg->has_glue()) {
                for (const ResourceRecord& ns : rcvd_msg->authorities) {
                    if (ns.type != RRType::NS)
                        continue;
                    ResolverResult res = co_await resolve({ns.rdata, QType::A, DNSClass::IN}, n_it);
                    if (res.status == ResolverStatus::Success)
                        break;
                }
            }

            if (rcvd_msg->header.nscount > 0)
                break;
        }
    }

    co_return ResolverResult{ResolverStatus::InternalError, RCode::ServFail};
}
