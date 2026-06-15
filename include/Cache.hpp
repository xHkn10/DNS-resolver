#pragma once

#include "types.hpp"

#include <chrono>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

class Message;

struct CacheEntry {
    std::vector<ResourceRecord> rrset;
    RCode code;
    std::chrono::steady_clock::time_point expires_at;
};

struct CacheKey {
    std::vector<u8> name;
    RRType rrtype;
    DNSClass rrclass;

    bool operator==(const CacheKey& o) const {
        return name == o.name && rrtype == o.rrtype && rrclass == o.rrclass;
    }
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& k) const {
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
    std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;

public:
    Cache();

    void
    put_positive(
        const CacheKey& k,
        const std::vector<ResourceRecord>& rrset
    );

    void
    put_negative(
        const CacheKey& k,
        RCode,
        u32 soa_ttl
    );

    void cache_msg(const Message& m);

    template <typename T>
    requires
    std::same_as<std::remove_cvref_t<T>, RRType>
    || std::same_as<std::remove_cvref_t<T>, QType>
    std::optional<CacheEntry>
    get(std::span<const u8> name, T type, DNSClass klass);

    std::optional<CacheEntry>
    get(CacheKey k);

    CacheEntry
    find_best_ns_rrset(const std::vector<u8>& name);
};
