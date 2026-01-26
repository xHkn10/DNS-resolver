#include "Cache.hpp"
#include "types.hpp"
#include "util.hpp"
#include <chrono>
#include <optional>
#include <vector>

void
Cache::put_positive(
    const CacheKey& k,
    const std::vector<ResourceRecord>& records
) {
    auto now = std::chrono::steady_clock::now();
    
    u32 min_ttl = 0xFFFFFFFF;
    for (const ResourceRecord& rr : records)
        if (rr.ttl < min_ttl)
            min_ttl = rr.ttl;

    cache_.insert_or_assign(
        k,
        CacheEntry{records, RCode::NoError, now + std::chrono::seconds(min_ttl)}
    );
}

void
Cache::put_negative(const CacheKey& k, RCode code, u32 soa_ttl) {
    cache_.insert_or_assign(
        k, 
        CacheEntry{{}, code, 
        std::chrono::steady_clock::now() + std::chrono::seconds(soa_ttl)}
    );
}

std::optional<CacheEntry>
Cache::get(const std::vector<u8>& name, RRType rrtype, DNSClass rrclass) {

    std::vector<u8> norm = util::normalize(name);
    auto it = cache_.find({norm, rrtype, rrclass});
    
    if (it == cache_.end())
        return std::nullopt;
    
    const auto now = std::chrono::steady_clock::now();

    if (now >= it->second.expires_at) {
        cache_.erase(it);
        return std::nullopt;
    }

    CacheEntry res = it->second;

    const auto rem = std::chrono::duration_cast<std::chrono::seconds>(
        res.expires_at - now
    ).count();
    
    for (ResourceRecord& rr : res.records)
        rr.ttl = rem;

    return res;
}
