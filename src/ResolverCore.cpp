#include "ResolverCore.hpp"
#include "AsyncTcpServer.hpp"
#include "ResolverStructs.hpp"
#include "Cache.hpp"
#include "types.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <cstddef>
#include <optional>
#include <vector>

namespace net = boost::asio;
using net::ip::tcp;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;


awaitable<size_t>
ResolverCore::query_in_udp(
    const ResourceRecord& rr,
    const std::vector<u8>& query_bytes,
    std::vector<u8>& buf
) {
    auto executor = co_await net::this_coro::executor;
    
    auto addr = net::ip::make_address_v4(
        *reinterpret_cast<const std::array<unsigned char, 4>*>(rr.rdata.data())
    );
    udp::socket server_sock{executor, udp::v4()};
    udp::endpoint target_endpoint{addr, 53};
    
    LOG("Queried " << util::dn_to_str(rr.name) << '\n');

    co_await server_sock.async_send_to(
        net::buffer(query_bytes), target_endpoint, use_awaitable
    );
    
    udp::endpoint sender;

    co_return
        co_await server_sock.async_receive_from(
            net::buffer(buf), sender, use_awaitable
        );
}

awaitable<size_t>
ResolverCore::query_in_tcp(
    const ResourceRecord& rr,
    const std::vector<u8>& query_bytes,
    std::vector<u8>& buf
) {
    auto executor = co_await net::this_coro::executor;

    auto addr = net::ip::make_address_v4(
        *reinterpret_cast<const std::array<unsigned char, 4>*>(rr.rdata.data())
    );
    tcp::endpoint target_endpoint{addr, 53};
    tcp::socket server_sock{executor};

    co_await server_sock.async_connect(target_endpoint, use_awaitable);
    co_await AsyncTcpServer::send_dns_bytes(server_sock, query_bytes);

    LOG("Queried " << util::dn_to_str(rr.name) << '\n');
    
    co_return 
        co_await AsyncTcpServer::rcv_dns_bytes(
            server_sock, buf
        );
}

std::optional<Message>
ResolverCore::parse_and_validate_response(
    std::vector<u8>& response,
    u16 id
) {
    if (response.size() < Header::HEADER_SZ)
        return std::nullopt;
    auto rcvd_msg = Message::deserialize(response);
    if (!rcvd_msg)
        return std::nullopt;
    if (rcvd_msg->header.id != id)
        return std::nullopt;
    RCode rcvd_msg_code = rcvd_msg->header.get_err_code();
    if (rcvd_msg_code != RCode::NoError && rcvd_msg_code != RCode::NXDomain)
        return std::nullopt;
    return rcvd_msg;
}

awaitable<ResolverResult>
ResolverCore::resolve(
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
ResolverCore::resolve(
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

        LOG("BEST NSS:\n" << util::dn_to_str(best_nss.rrset.front().rdata) << '\n');

        util::shuffle(best_nss.rrset);

        std::vector<ResourceRecord> a_records;
        for (const ResourceRecord& ns : best_nss.rrset) {
            auto entry = cache.get(ns.rdata, RRType::A, DNSClass::IN);
            if (entry)
                a_records.insert(a_records.end(), entry->rrset.begin(), entry->rrset.end());
        }
        util::shuffle(a_records);

        for (const ResourceRecord& rr : a_records) {
            std::vector<u8> response(4096);
            size_t n = co_await query_in_udp(rr, *query_bytes, response);
            response.resize(n);

            LOG("Received " << n << " bytes from " << util::dn_to_str(rr.name) << '\n');
            
            auto rcvd_msg = parse_and_validate_response(response, query_msg.header.id);
            if (!rcvd_msg)
                continue;

            if (rcvd_msg->header.is_tc()) {
                LOG("Switching to TCP\n");

                response.resize(4096);
                n = co_await query_in_tcp(rr, *query_bytes, response);
                
                LOG("Received " << n << " bytes from " << util::dn_to_str(rr.name) << '\n');

                rcvd_msg = parse_and_validate_response(response, query_msg.header.id);
                if (!rcvd_msg)
                    continue;
            }
            
            cache.cache_msg(*rcvd_msg);

            if (rcvd_msg->header.is_authoritative())
                co_return ResolverResult{
                    ResolverStatus::Success,
                    rcvd_msg->header.get_err_code(),
                    *rcvd_msg
                };

            if (!rcvd_msg->has_glue()) {
                LOG("No glue records\n");
                
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
