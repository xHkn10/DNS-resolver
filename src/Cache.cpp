#include "Cache.hpp"
#include "Message.hpp"
#include "types.hpp"
#include "util.hpp"
#include "constants.hpp"
#include <chrono>
#include <concepts>
#include <optional>
#include <span>
#include <vector>

Cache::Cache() {
    for (const ResourceRecord& rr : dns::roots::ALL)
        put_positive({rr.name, rr.type, rr.klass}, {rr});

    std::vector<ResourceRecord> root_ns_rrset;
    for (const ResourceRecord& rr : dns::roots::ALL)
        root_ns_rrset.emplace_back(std::vector<u8>{1, '.', 0}, RRType::NS, DNSClass::IN, rr.ttl, rr.name.size(), rr.name);

    put_positive({{1, '.', 0}, RRType::NS, DNSClass::IN}, root_ns_rrset);
}

void
Cache::put_positive(
    const CacheKey& k,
    const std::vector<ResourceRecord>& rrset
) {
    auto now = std::chrono::steady_clock::now();
    
    u32 min_ttl = 0xFFFFFFFFU;
    for (const ResourceRecord& rr : rrset)
        if (rr.ttl < min_ttl)
            min_ttl = rr.ttl;

    cache_.insert_or_assign(
        k,
        CacheEntry{rrset, RCode::NoError, now + std::chrono::seconds(min_ttl)}
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

template std::optional<CacheEntry>
Cache::get<QType>(std::span<const u8>, QType, DNSClass);
template std::optional<CacheEntry>
Cache::get<RRType>(std::span<const u8>, RRType, DNSClass);

template <typename T>
requires
std::same_as<std::remove_cvref_t<T>, RRType>
|| std::same_as<std::remove_cvref_t<T>, QType>
std::optional<CacheEntry>
Cache::get(std::span<const u8> name, T type, DNSClass klass) {

    std::vector<u8> norm = util::normalize(name);
    auto it = cache_.find({norm, static_cast<RRType>(type), klass});
    
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
    
    for (ResourceRecord& rr : res.rrset)
        rr.ttl = rem;

    return res;
}


std::optional<CacheEntry>
Cache::get(CacheKey k) {

    k.name = util::normalize(k.name);
    auto it = cache_.find(k);
    
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
    
    for (ResourceRecord& rr : res.rrset)
        rr.ttl = rem;

    return res;
}

CacheEntry
Cache::find_best_ns_rrset(const std::vector<u8>& name) {
    std::span<const u8> vw = name;
    size_t start = 0;
    while (true) {
        auto entry = get(vw.subspan(start), RRType::NS, DNSClass::IN);
        if (entry)
            return *entry;
        if (start >= name.size() || name[start] == 0)
            break;
        start += name[start] + 1;
    }
    
    return *get(std::vector<u8>{1, '.', 0}, RRType::NS, DNSClass::IN);
}

void
Cache::cache_msg(const Message& m) {

    std::unordered_map<CacheKey, std::vector<ResourceRecord>, CacheKeyHash> grp;
    const ResourceRecord* soa = nullptr;

    for (const ResourceRecord& rr : m.authorities)
        if (rr.type == RRType::NS)
            grp[{rr.name, RRType::NS, rr.klass}].push_back(rr);
        else if (rr.type == RRType::SOA)
            soa = &rr;
    
    for (const ResourceRecord& rr : m.answers)
        grp[{rr.name, rr.type, rr.klass}].push_back(rr);

    for (const ResourceRecord& rr : m.additional)
        if (rr.type == RRType::A || rr.type == RRType::AAAA)
            grp[{rr.name, rr.type, rr.klass}].push_back(rr);

    if (soa && m.header.ancount == 0) {
        u32 soa_minimum;
        std::memcpy(&soa_minimum, soa->rdata.data() + soa->rdata.size() - 4, 4);
        put_negative({
            m.questions.front().qname,
            static_cast<RRType>(m.questions.front().type),
            m.questions.front().klass
        }, m.header.get_err_code(), soa_minimum);
    }

    for (auto& [k, rrset] : grp)
        put_positive(k, rrset);
}