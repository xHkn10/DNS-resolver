#include "Message.hpp"
#include "SyncUdpResolver.hpp"
#include "Cache.hpp"
#include "types.hpp"
#include "util.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstddef>
#include <optional>
#include <unistd.h>
#include <iostream>
#include <vector>


SyncUdpResolver::SyncUdpResolver(u16 port, size_t max_buffer_sz) 
: port(port), max_buffer_sz(max_buffer_sz) {}

bool
SyncUdpResolver::init() {
    listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(port);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
        listen_sock,
        reinterpret_cast<sockaddr*>(&listen_addr),
        sizeof(listen_addr)
    ) == -1) {
        perror("bind");
        close(listen_sock);
        return false;
    }

    cache = Cache{};

    return true;
}

bool
SyncUdpResolver::listen() {
    while (true) {
        sockaddr_in cli_addr;
        socklen_t cli_addr_len = sizeof(cli_addr);
        
        std::vector<u8> packet(max_buffer_sz);
        ssize_t n = recvfrom(
            listen_sock, packet.data(), packet.size(), 0,
            reinterpret_cast<sockaddr*>(&cli_addr),
            &cli_addr_len
        );

        if (n == -1) {
            perror("recvfrom");
            continue;
        } else if (n < Header::HEADER_SZ)
            continue;
        
        packet.resize(n);

        auto cli_query = Message::deserialize(packet);
        if (!cli_query) {
            send_formerr(cli_addr, cli_addr_len, packet);
            continue;
        }
        ClientContext cli_ctx{
            .addr = cli_addr,
            .addr_len = cli_addr_len,
            .id = cli_query->header.id
        };
        cli_query->assign_edns_related_fields(cli_ctx);
    

        if (!cli_query->header.is_rd()) {
            send_servfail(cli_addr, cli_addr_len, packet);
            continue;
        }
        if (cli_query->questions.size() == 0)
            continue;

        ResolverResult res = resolve(cli_query->questions.front());

        if (res.status != ResolverStatus::Success) {
            send_servfail(cli_addr, cli_addr_len, packet);
            continue;
        }
        
        finalize_response(res, cli_ctx);

        auto send_to_cli_bytes = res.msg.serialize();
        if (!send_to_cli_bytes)
            continue;

        sendto(
            listen_sock, send_to_cli_bytes->data(), send_to_cli_bytes->size(), 0,
            reinterpret_cast<sockaddr*>(&cli_addr),
            cli_addr_len
        );

        std::cout << "Response sent\n";
    }

    close(listen_sock);
}

void
SyncUdpResolver::finalize_response(
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

void
SyncUdpResolver::send_servfail(
    const sockaddr_in& cli_addr,
    socklen_t cli_addr_len,
    std::vector<u8>& packet
) {
    memset(packet.data() + 2, 0, (packet.size() - 2) * sizeof(u8));
    packet[2] |= 0x80; // qr bit set
    packet[3] |= 0x80; // ra bit set
    packet[3] |= static_cast<u8>(RCode::ServFail);
    sendto(
        listen_sock, packet.data(), Header::HEADER_SZ, 0,
        reinterpret_cast<const sockaddr*>(&cli_addr),
        cli_addr_len
    );
}

void
SyncUdpResolver::send_formerr(
    const sockaddr_in& cli_addr,
    socklen_t cli_addr_len,
    std::vector<u8>& packet
) {
    std::cerr << "Malformed DNS packet from client\n";
    memset(packet.data() + 2, 0, (packet.size() - 2) * sizeof(u8));
    packet[2] |= 0x80; // qr bit set
    packet[3] |= 0x80; // ra bit set
    packet[3] |= static_cast<u8>(RCode::FormErr);
    sendto(
        listen_sock, packet.data(), Header::HEADER_SZ, 0,
        reinterpret_cast<const sockaddr*>(&cli_addr),
        cli_addr_len
    );
}


ResolverResult
SyncUdpResolver::resolve(const Question& q) {

    if (q.type == QType::ANY)
        return {ResolverStatus::Success, RCode::NotImp};

    Question active_query = q;
    std::vector<ResourceRecord> chain;

    {
        int limit = 8; // follow cname chain
        while (true) {
            if (--limit < 0)
                break;
            auto entry = cache.get(active_query.qname, q.type, q.klass);
            if (entry)
                return {
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
    
    int it = max_iterations;
    while (true) {
        if (it < 0)
            break;

        ResolverResult res = resolve(active_query, it);
        if (res.status != ResolverStatus::Success)
            return res;

        for (const ResourceRecord& rr : res.msg.answers) {
            if (rr.type == static_cast<RRType>(q.type)) {
                res.msg.answers.insert(res.msg.answers.begin(), chain.begin(), chain.end());
                res.msg.header.ancount = res.msg.answers.size();
                res.msg.questions.resize(1);
                res.msg.questions.front() = q;
                res.msg.header.qdcount = 1;
                return res;                
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
            return res;
    }

    return {ResolverStatus::LoopDetected, RCode::ServFail};
}


ResolverResult
SyncUdpResolver::resolve(const Question& q, int& n_it) {
    
    Message query_msg = Message::from_question(q);
    auto bytes = query_msg.serialize();
    if (!bytes)
        return {ResolverStatus::InternalError, RCode::ServFail};

    while (true) {
        if (--n_it < 0)
            break;

        CacheEntry best_nss = cache.find_best_ns_rrset(q.qname);
        util::shuffle(best_nss.rrset);

        std::vector<ResourceRecord> a_records;
        for (const ResourceRecord& ns : best_nss.rrset) {
            auto entry = cache.get(ns.rdata, RRType::A, DNSClass::IN);
            if (entry)
                a_records.insert(a_records.end(), entry->rrset.begin(), entry->rrset.end());
        }
        util::shuffle(a_records);

        for (const ResourceRecord& a_record : a_records) {
            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            sockaddr_in send_addr{.sin_family=AF_INET, .sin_port=htons(DNS_PORT)};
            std::memcpy(&send_addr.sin_addr.s_addr, a_record.rdata.data(), 4);

            if (connect(
                sockfd,
                reinterpret_cast<sockaddr*>(&send_addr),
                sizeof(send_addr)
            ) == -1) {
                perror("connect");
                close(sockfd);
                continue;
            }

            send(sockfd, bytes->data(), bytes->size(), 0);
            std::vector<u8> buffer(max_buffer_sz);
            ssize_t n = recv(sockfd, buffer.data(), buffer.size(), 0);

            if (n == -1) {
                perror("recv");
                close(sockfd);
                continue;
            }
            if (n < Header::HEADER_SZ) {
                close(sockfd);
                continue;
            }
            buffer.resize(n);

            auto rcvd_msg = Message::deserialize(buffer);
            if (!rcvd_msg) {
                close(sockfd);
                continue;
            }
            RCode rcvd_msg_code = rcvd_msg->header.get_err_code();

            if (rcvd_msg->header.id != query_msg.header.id)
                continue;
            if (rcvd_msg_code != RCode::NoError && rcvd_msg_code != RCode::NXDomain)
                continue;
            
            cache.cache_msg(*rcvd_msg);

            if (rcvd_msg->header.is_authoritative())
                return {ResolverStatus::Success, rcvd_msg_code, *rcvd_msg};

            if (!rcvd_msg->has_glue()) {
                for (const ResourceRecord& ns : rcvd_msg->authorities) {
                    if (ns.type != RRType::NS)
                        continue;
                    ResolverResult res = resolve({ns.rdata, QType::A, DNSClass::IN}, n_it);
                    if (res.status == ResolverStatus::Success)
                        break;
                }
            }

            if (rcvd_msg->header.nscount > 0)
                break;
        }
    }

    return {ResolverStatus::LoopDetected, RCode::ServFail};
}
