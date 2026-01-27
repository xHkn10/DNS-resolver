#include "Message.hpp"
#include "Resolver.hpp"
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


Resolver::Resolver(u16 port, size_t max_buffer_sz) 
: port(port), max_buffer_sz(max_buffer_sz) {}

bool
Resolver::init() {
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
Resolver::listen() {
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

        ResolverResult res = resolve(cli_query->questions.front());

        if (res.status != ResolverStatus::Success) {
            send_servfail(cli_addr, cli_addr_len, packet);
            continue;
        }
        
        finalize_response(res.rcvd_msg, res, cli_ctx);

        auto send_to_cli_bytes = res.rcvd_msg.serialize();

        if (!send_to_cli_bytes) {
            std::cerr << "Error\n";
            continue;
        }

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
Resolver::finalize_response(
    Message& m,
    ResolverResult res,
    const ClientContext& cli
) {
    m.header.id = cli.id;
    m.header.set_qr_bit();
    m.header.set_rd_bit();
    m.header.set_ra_bit();
    m.header.clear_aa_bit();
    m.header.set_errcode(res.code);
    if (res.status == ResolverStatus::Success) {
        if (m.header.ancount > 0)
            m.strip_sections();
        else {
            m.additional.clear();
            m.header.arcount = 0;
        }
        if (cli.uses_edns)
            m.put_edns_opt();
    }

    if (m.size() > cli.max_payload)
        m.truncate_msg(cli.max_payload);
}

void
Resolver::send_servfail(
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
Resolver::send_formerr(
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
Resolver::resolve(const Question& q) {
    int it = max_iterations;
    return resolve(q, it);
}

// dig @localhost www.brother.in -p 3169 
ResolverResult
Resolver::resolve(const Question& q, int& n_iterations) {
    {
        {
            auto entry = cache.get(q.qname, static_cast<RRType>(q.qtype), q.qclass);
            if (entry) {
                Message ret = Message::from_cache_entry(*entry, q);
                return {ResolverStatus::Success, entry->code, ret};
            }
        }

        int limit = 8; // follow cname chain
        std::vector<u8> cur = q.qname;
        std::vector<ResourceRecord> chain;
        while (true) {
            if (--limit == 0)
                break;
            auto cname = cache.get(cur, RRType::CNAME, DNSClass::IN);
            if (cname && cname->rrset.size() > 0) {
                chain.push_back(cname->rrset.front());
                auto entry = cache.get(
                    cname->rrset.front().rdata,
                    static_cast<RRType>(q.qtype),
                    q.qclass
                );
                if (entry) {
                    Message ret = Message::from_cache_entry(chain, *entry, q);
                    return {ResolverStatus::Success, entry->code, ret};
                }
                cur = cname->rrset.front().rdata;
            } else break;
        }
    }

    Message query_msg = Message::from_question(q);
    auto bytes = query_msg.serialize();
    if (!bytes)
        return {ResolverStatus::InternalError, RCode::ServFail};

    while (true) {
        if (--n_iterations == 0)
            break;

        CacheEntry best_nss = cache.find_best_ns_rrset(q.qname);
        std::vector<ResourceRecord> a_records;
        for (const ResourceRecord& ns : best_nss.rrset) {
            auto entry = cache.get(ns.rdata, RRType::A, DNSClass::IN);
            if (entry)
                a_records.insert(a_records.end(), entry->rrset.begin(), entry->rrset.end());
        }

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

            if (rcvd_msg->header.arcount <= 1) {
                for (const ResourceRecord& ns : rcvd_msg->authorities) {
                    if (ns.rrtype != RRType::NS)
                        continue;
                    ResolverResult res = resolve({ns.rdata, QType::A, DNSClass::IN}, n_iterations);
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
