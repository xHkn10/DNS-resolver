#include "Message.hpp"
#include "Resolver.hpp"
#include "Cache.hpp"
#include "constants.hpp"
#include "types.hpp"
#include "util.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstddef>
#include <optional>
#include <unistd.h>
#include <iostream>
#include <unordered_map>
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

        Message send_to_cli_msg;
        ResolverResult res = resolve(*cli_query, send_to_cli_msg, cli_ctx);

        if (res.status != ResolverStatus::Success) {
            send_servfail(cli_addr, cli_addr_len, packet);
            continue;
        }
        
        finalize_response(send_to_cli_msg, res, cli_ctx);

        auto send_to_cli_bytes = send_to_cli_msg.serialize();

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
Resolver::resolve(
    const Message& cli_query,
    Message& send_to_cli,
    ClientContext& cli_ctx
) {
    std::vector<ResourceRecord> adds = dns::roots::ALL;
    std::vector<ResourceRecord> auths;
    
    Message msg = cli_query.from_questions();
    auto bytes = msg.serialize();

    auto entry = cache.get(
        msg.questions.front().qname,
        static_cast<RRType>(msg.questions.front().qtype),
        msg.questions.front().qclass
    );
    
    if (entry) {
        std::cout << "Cache hit\n";
        send_to_cli = std::move(msg);
        send_to_cli.answers = entry->records;
        send_to_cli.header.ancount = entry->records.size();
        return {ResolverStatus::Success, entry->code};
    }
    
    std::cout << "Cache miss\n";

    if (!bytes)
        return {ResolverStatus::InternalError, RCode::ServFail};
    
    while (true) {
        if (--cli_ctx.max_iterations == 0) {
            send_to_cli.header.flags |= static_cast<u16>(RCode::ServFail);
            return {ResolverStatus::LoopDetected, RCode::ServFail};
        }

        bool authority_section = false;
        bool additional_section = false;

        for (const auto& rr : adds) {
            if (rr.rrtype != RRType::A)
                continue;

            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            sockaddr_in send_addr{.sin_family=AF_INET, .sin_port=htons(DNS_PORT)};
            std::memcpy(&send_addr.sin_addr.s_addr, rr.rdata.data(), 4);

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

            std::cout << "waiting for " << util::dn_to_str(rr.name) << '\n';
            
            ssize_t n = recv(sockfd, buffer.data(), max_buffer_sz, 0);
            close(sockfd);

            if (n == -1) {
                perror("recv");
                std::cerr << util::dn_to_str(rr.name) << " failed\n";
                continue;
            }

            std::cout << "received " << n << " bytes from " << util::dn_to_str(rr.name) << '\n';
            
            if (n < Header::HEADER_SZ)
                continue;
            
            buffer.resize(n);
            auto rcvd_msg = Message::deserialize(buffer);

            if (!rcvd_msg || rcvd_msg->header.id != msg.header.id)
                continue;

            auto cache_section = [&](const std::vector<ResourceRecord>& rrs) {
                std::unordered_map<CacheKey, std::vector<ResourceRecord>, CacheKeyHash> groups;
                for (const ResourceRecord& rr : rrs)
                    groups[{rr.name, rr.rrtype, rr.rrclass}].push_back(rr);
                for (auto& [key, records] : groups)
                    cache.put_positive(key, records);
            };

            // cache_section(rcvd_msg->authorities);
            // cache_section(rcvd_msg->additional);

            if (rcvd_msg->header.is_authoritative()) {
                if (rcvd_msg->header.ancount > 0) {
                    std::cout << "ANSWER FOUND to " << util::dn_to_str(rcvd_msg->questions.front().qname) << '\n' << util::bytes_to_ipv4(rcvd_msg->answers.front().rdata) << '\n';

                    cache_section(rcvd_msg->answers);

                    send_to_cli = std::move(*rcvd_msg);
                    return {ResolverStatus::Success, RCode::NoError};
                }

                RCode code = rcvd_msg->header.get_err_code();
                std::cerr << "Authoritative server sent error code " << code << '\n';

                if (code == RCode::NXDomain || code == RCode::NoError) {
                    u32 soa_ttl = 300;
                    for (const ResourceRecord& rr : rcvd_msg->authorities) {
                        if (rr.rrtype == RRType::SOA) {
                            u32 soa_min;
                            std::memcpy(&soa_min, rr.rdata.data() + rr.rdata.size() - 4, 4);
                            soa_ttl = rr.ttl < soa_ttl ? rr.ttl : soa_ttl;
                            soa_ttl = soa_min < soa_ttl ? soa_min : soa_ttl;
                        }
                    }

                    cache.put_negative({
                        msg.questions.front().qname,
                        static_cast<RRType>(msg.questions.front().qtype),
                        msg.questions.front().qclass
                    }, code, soa_ttl);

                    send_to_cli = std::move(*rcvd_msg);
                    return {ResolverStatus::Success, code};
                }

                continue;
            }

            if (rcvd_msg->header.nscount == 0)
                continue;

            authority_section = true;
            auths = std::move(rcvd_msg->authorities);

            if (rcvd_msg->has_glue()) {
                additional_section = true;
                adds = std::move(rcvd_msg->additional);
            }
            
            break;
        }

        if (!authority_section)
            return {ResolverStatus::NoCandidates, RCode::ServFail};

        if (!additional_section) {
            bool found_ans = false;
            for (const ResourceRecord& rr : auths) {
                Message new_task;
                if (rr.rrtype == RRType::NS)
                    new_task.questions.emplace_back(rr.rdata, QType::A, DNSClass::IN);
                else
                    continue;
                new_task.header.qdcount = 1;
                new_task.put_edns_opt();
                new_task.put_random_id();
    
                Message ans;
                ResolverResult res = resolve(new_task, ans, cli_ctx);
        
                if (res) {
                    adds = std::move(ans.answers);
                    found_ans = true;
                    break;
                }
            }

            if (!found_ans)
                return {ResolverStatus::NoCandidates, RCode::ServFail};
        }
    }

    return {ResolverStatus::NoCandidates, RCode::ServFail};
}
