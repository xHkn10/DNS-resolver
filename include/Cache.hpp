#pragma once

#include "types.hpp"
#include <chrono>
#include <optional>
#include <unordered_map>
#include <vector>

struct CacheEntry {
    std::vector<ResourceRecord> records;
    RCode code;
    std::chrono::steady_clock::time_point expires_at;
};

struct CacheKey {
    std::vector<u8> name;
    RRType rrtype;
    DNSClass rrclass;
    inline bool operator==(const CacheKey& o) const {
        return name == o.name && rrtype == o.rrtype && rrclass == o.rrclass;
    }
};

struct CacheKeyHash {
    inline size_t operator()(const CacheKey& k) const {
        size_t h =
        std::hash<int>{}(static_cast<int>(k.rrtype))
        ^
        std::hash<int>{}(static_cast<int>(k.rrclass));
        
        for (u8 b : k.name)
            h ^= std::hash<u8>{}(b) + 0x9e3779b9 + (h << 6) + (h >> 2);

        return h;
    }
};

class Cache {
private:
    std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;

public:
    void
    put_positive(
        const CacheKey& k,
        const std::vector<ResourceRecord>& rrs
    );

    void
    put_negative(
        const CacheKey& k,
        RCode,
        u32 soa_ttl
    );

    std::optional<CacheEntry>
    get(const std::vector<u8>& name, RRType rrtype, DNSClass rrclass);
};
