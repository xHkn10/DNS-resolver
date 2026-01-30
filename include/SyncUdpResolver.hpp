#pragma once

#include "Cache.hpp"
#include "types.hpp"
#include <netinet/in.h>

struct ResolverResult;

class SyncUdpResolver {
private:
    const u16 port = 3169;
    const size_t max_buffer_sz = 8192;
public:
    int listen_sock;
    sockaddr_in listen_addr;
    const int max_iterations = 30;
    Cache cache;

public:
    SyncUdpResolver(u16 port, size_t max_buffer_sz);
    SyncUdpResolver() = default;
    bool init();
    bool listen();

private:
    ResolverResult
    resolve(const Question& q);

    ResolverResult
    resolve(const Question& q, int& n_it);
    
    void
    send_formerr(
        const sockaddr_in& cli_addr,
        socklen_t cli_addr_len,
        std::vector<u8>& packet
    );
    void
    send_servfail(
        const sockaddr_in& cli_addr,
        socklen_t cli_addr_len,
        std::vector<u8>& packet
    );

    void
    finalize_response(ResolverResult& res, const ClientContext& cli);
};
