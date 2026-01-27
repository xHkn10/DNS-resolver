#pragma once

#include "Cache.hpp"
#include "Message.hpp"
#include "types.hpp"
#include <netinet/in.h>

enum class ResolverStatus {
    Success,         // Found an answer OR authoritative proof of non-existence
    LoopDetected,    // Fatal: CNAME loop or depth exceeded
    NoCandidates,    // Fatal: Checked all NS records and all failed
    InternalError    // Fatal: Serialization failed, etc.
};

struct ResolverResult {
    ResolverStatus status;
    RCode code;
    Message rcvd_msg;
    explicit operator bool() {
        return status == ResolverStatus::Success;
    }
};

class Resolver {
private:
    const u16 port = 3169;
    const size_t max_buffer_sz = 8192;
public:
    int listen_sock;
    sockaddr_in listen_addr;
    const int max_iterations = 30;
    Cache cache;

public:
    Resolver(u16 port, size_t max_buffer_sz);
    Resolver() = default;
    bool init();
    bool listen();

private:
    ResolverResult
    resolve(const Question& q);

    ResolverResult
    resolve(const Question& q, int& n_iterations);
    
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
    finalize_response(Message& m, ResolverResult res, const ClientContext& cli);
};
