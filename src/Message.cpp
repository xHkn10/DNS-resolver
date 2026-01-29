#include "Message.hpp"
#include "Cache.hpp"
#include "util.hpp"
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <types.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <vector>

static_assert(
    Header::HEADER_SZ == sizeof(Header),
    "Something went wrong in header size\n"
);

namespace {
    template <typename T>
    inline void 
    read_u16(T& to, const std::vector<u8>& packet, size_t& cursor) {
        to = static_cast<T>(
            static_cast<u16>(packet[cursor]) << 8
            | static_cast<u16>(packet[cursor + 1])
        );
        cursor += 2;
    }
    template <typename T>
    inline void
    read_u32(T& to, const std::vector<u8>& packet, size_t& cursor) {
        to = static_cast<T>(
            (static_cast<u32>(packet[cursor]) << 24)
            | (static_cast<u32>(packet[cursor + 1]) << 16)
            | (static_cast<u32>(packet[cursor + 2]) << 8)
            | static_cast<u32>(packet[cursor + 3])
        );
        cursor += 4;
    }
    template <typename T>
    inline void
    write_u16(T src, std::vector<u8>& dst, size_t& cursor) {
        dst[cursor++] = static_cast<u8>(static_cast<u16>(src) >> 8);
        dst[cursor++] = static_cast<u8>(static_cast<u16>(src));
    }
    template <typename T>
    inline void
    write_u32(T src, std::vector<u8>& dst, size_t& cursor) {
        dst[cursor++] = static_cast<u8>(static_cast<u32>(src) >> 24);
        dst[cursor++] = static_cast<u8>(static_cast<u32>(src) >> 16);
        dst[cursor++] = static_cast<u8>(static_cast<u32>(src) >> 8);
        dst[cursor++] = static_cast<u8>(static_cast<u32>(src));
    }

    inline bool
    bound_check(size_t cursor, size_t bytes_to_read, size_t sz) {
        if (cursor + bytes_to_read > sz) {
            std::cerr << "Buffer overflow\n";
            return true;
        }
        return false;
    }
}

void
Message::put_random_id() {
    header.id = std::uniform_int_distribution<u16>{0, 65535}(util::seed());
}

void
Message::put_edns_opt() {
    additional.emplace_back(
        std::vector<u8>{0}, RRType::OPT, static_cast<DNSClass>(4096), 0, 0
    );
    ++header.arcount;
}

const ResourceRecord*
Message::get_edns_opt_record() const {
    for (const ResourceRecord& rr : additional)
        if (rr.type == RRType::OPT)
            return &rr;
    return nullptr;
}

void
Message::assign_edns_related_fields(ClientContext& cli) const {
    const ResourceRecord* opt = get_edns_opt_record();
    if (opt == nullptr)
        return;
    cli.uses_edns = true;
    cli.max_payload = static_cast<u16>(opt->klass);
    cli.wants_dnssec = static_cast<bool>(opt->ttl & 0x8000);
}

size_t
Message::size() const {
    size_t res = Header::HEADER_SZ;
    for (const Question& q : questions)
        res += q.qname.size() + 4;
    for (const ResourceRecord& rr : answers)
        res += rr.name.size() + 10 + rr.rdata.size();
    for (const ResourceRecord& rr : authorities)
        res += rr.name.size() + 10 + rr.rdata.size();
    for (const ResourceRecord& rr : additional)
        res += rr.name.size() + 10 + rr.rdata.size();
    return res;
}

void
Message::truncate_msg(size_t max_sz) {
    header.set_tc_bit();
    additional.clear();
    header.arcount = 0;
    authorities.clear();
    header.nscount = 0;
    if (size() > max_sz) {
        answers.clear();
        header.ancount = 0;
    }
}

void
Message::strip_sections() {
    authorities.clear();
    header.nscount = 0;
    additional.clear();
    header.arcount = 0;
}

bool
Message::has_glue() const {
    for (const ResourceRecord& rr : additional)
        if (rr.type == RRType::A)
            return true;
    return false;
}

Message
Message::from_question(const Question &q) {
    Message res{};
    
    res.questions.push_back(q);
    res.header.qdcount = 1;
    res.put_edns_opt();
    auto& gen = util::seed();
    res.header.id = std::uniform_int_distribution<u16>{0, 65535}(gen);
    res.header.flags = 0x0000;
    
    return res;
}

Message
Message::from_cache_entry(
    const CacheEntry& entry,
    const Question& q
) {
    Message res;
    res.header.flags |= static_cast<u32>(entry.code);
    res.header.ancount = entry.rrset.size();
    res.answers = entry.rrset;
    res.header.qdcount = 1;
    res.questions.push_back(q);
    return res;
}

Message
Message::from_cache_entry(
    const std::vector<ResourceRecord>& chain,
    const CacheEntry& entry,
    const Question& q
) {
    Message res;
    res.header.flags |= static_cast<u32>(entry.code);
    res.header.ancount = chain.size() + entry.rrset.size();
    res.answers = chain;
    res.answers.insert(res.answers.end(), entry.rrset.begin(), entry.rrset.end());
    res.header.qdcount = 1;
    res.questions.push_back(q);
    return res;
}

std::optional<std::vector<u8>>
Message::serialize() const {
    std::vector<u8> packet(8192);
    size_t cursor = 0;
    auto get_dn_len = [](std::span<const u8> dn) {
        size_t total_len = 0;
        while (true) {
            u8 label_len = dn[total_len];
            if (label_len == 0)
                break;
            total_len += label_len + 1;
        }
        ++total_len;
        return total_len;
    };
    auto serialize_dn = [&](std::span<const u8> dn) {
        size_t total_len = get_dn_len(dn);

        if (bound_check(cursor, total_len, packet.size()))
            return false;
        
        std::memcpy(packet.data() + cursor, dn.data(), total_len);
        cursor += total_len;
        return true;
    };
    auto serialize_opt_record = [&cursor, &packet](std::span<const u8> data) {
        for (size_t i{}; i < data.size(); ) {
            if (bound_check(cursor, 4, packet.size()))
                return false;
            std::memcpy(packet.data() + cursor, data.data() + i, 2);
            cursor += 2, i += 2;
            u16 opt_len = (data[i] << 8) | data[i + 1];
            std::memcpy(packet.data() + cursor, data.data() + i, 2);
            cursor += 2, i += 2;
            if (bound_check(cursor, opt_len, packet.size()))
                return false;
            for (i32 j = 0; j < opt_len; ++j)
                packet[cursor++] = data[i++];
        }
        return true;
    };
    auto serialize_ipv4 = [&cursor, &packet](std::span<const u8> v) {
        if (bound_check(cursor, 4, packet.size()))
            return false;
        std::memcpy(packet.data() + cursor, v.data(), 4);
        cursor += 4;
        return true;
    };
    auto serialize_ipv6 = [&cursor, &packet](std::span<const u8> v) {
        if (bound_check(cursor, 16, packet.size()))
            return false;
        std::memcpy(packet.data() + cursor, v.data(), 16);
        cursor += 16;
        return true;
    };
    auto serialize_soa_record = [&](std::span<const u8> v) {
        size_t mname_len = get_dn_len(v);
        size_t rname_len = get_dn_len(v.subspan(mname_len));
        if (!serialize_dn(v))
            return false;
        if (!serialize_dn(v.subspan(mname_len)))
            return false;
        if (bound_check(cursor, 20, packet.size()))
            return false;
        std::memcpy(packet.data() + cursor, v.data() + mname_len + rname_len, 20);
        cursor += 20;
        return true;
    };
    auto serialize_mx = [&](std::span<const u8> v) {
        if (bound_check(cursor, 2, packet.size()))
            return false;
        std::memcpy(packet.data() + cursor, v.data(), 2);
        cursor += 2;
        if (!serialize_dn(v.subspan(2)))
            return false;
        return true;
    };
    auto serialize_txt = [&](std::span<const u8> v, u16 rdlen) {
        size_t consumed = 0;
        while (consumed < rdlen) {
            if (bound_check(cursor, 1, packet.size()))
                return false;
            u8 len = v[consumed++];
            packet[cursor++] = len;
            if (bound_check(cursor, len, packet.size()))
                return false;
            std::memcpy(packet.data() + cursor, v.data() + consumed, len);
            consumed += len, cursor += len;
        }
        return true;
    };
    auto serialize_srv = [&](std::span<const u8> v) {
        if (bound_check(cursor, 6, packet.size()))
            return false;
        std::memcpy(packet.data() + cursor, v.data(), 6);
        if (!serialize_dn(v.subspan(6)))
            return false;
        return true;
    };

    write_u16(header.id, packet, cursor);
    write_u16(header.flags, packet, cursor);
    write_u16(header.qdcount, packet, cursor);
    write_u16(header.ancount, packet, cursor);
    write_u16(header.nscount, packet, cursor);
    write_u16(header.arcount, packet, cursor);

    for (const Question& q : questions) {
        if (!serialize_dn(q.qname))
            return std::nullopt;
        if (bound_check(cursor, 4, packet.size()))
            return std::nullopt;
        write_u16(static_cast<u16>(q.type), packet, cursor);
        write_u16(static_cast<u16>(q.klass), packet, cursor);
    }

    for (const auto* v : {&answers, &authorities, &additional}) {
        for (const ResourceRecord& rr : *v) {
            if (!serialize_dn(rr.name))
                return std::nullopt;
            if (bound_check(cursor, 10, packet.size()))
                return std::nullopt;
            
            write_u16(static_cast<u16>(rr.type), packet, cursor);
            write_u16(static_cast<u16>(rr.klass), packet, cursor);
            write_u32(rr.ttl, packet, cursor);
            write_u16(rr.rdlength, packet, cursor);

            switch (rr.type) {
                case RRType::A:
                    if (!serialize_ipv4(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::AAAA:
                    if (!serialize_ipv6(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::NS: [[fallthrough]];
                case RRType::CNAME: [[fallthrough]];
                case RRType::PTR:
                    if (!serialize_dn(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::OPT:
                    if (!serialize_opt_record(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::SOA:
                    if (!serialize_soa_record(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::MX:
                    if (!serialize_mx(rr.rdata))
                        return std::nullopt;
                    break;
                case RRType::TXT:
                    if (!serialize_txt(rr.rdata, rr.rdlength))
                        return std::nullopt;
                    break;
                case RRType::SRV:
                    if (!serialize_srv(rr.rdata))
                        return std::nullopt;
                    break;
                default:
                    std::cerr << "type " << rr.type << " to be implemented\n";
                    break;
            }
        }
    }

    packet.resize(cursor);
    return packet;
}

std::optional<Message>
Message::deserialize(const std::vector<u8>& packet) {
    Message msg{};
    if (!msg.deserialize_all_(packet))
        return std::nullopt;
    return msg;
}

std::string Message::rdata_to_string(const ResourceRecord& rr) {
    std::string res;
    switch (rr.type) {
        case RRType::A:
            for (i32 i = 0; i < 4; ++i) {
                res.append(std::to_string(rr.rdata[i]));
                if (i != 3)
                    res.push_back('.');
            }
            break;
        case RRType::CNAME: [[fallthrough]];
        case RRType::PTR: [[fallthrough]];
        case RRType::NS:
            for (i32 i{0}; ; ) {
                u8 label_len = rr.rdata[i++];
                if (label_len == 0)
                    break;
                while (label_len--)
                    res.push_back(static_cast<char>(rr.rdata[i++]));
            }
            break;
        case RRType::AAAA: {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (i32 i{0}; i < 8; ) {
                u16 sh = (
                    static_cast<u16>(rr.rdata[i]) << 8
                ) | rr.rdata[i + 1];
                ss << std::setw(4) << sh;
                if (i != 7)
                    ss << ':';
                i += 2;
            }
            res = ss.str();
        }
        default:
            std::cerr
            << "rdata_to_string not implemented for rrtye "
            << static_cast<u16>(rr.type) << '\n';
            break;
    }
    return res;
}

bool 
Message::deserialize_all_(const std::vector<u8>& packet) {
    size_t cursor = 0;

    if (!deserialize_header_(packet, cursor))
        return false;
    for (i32 i = 0; i < header.qdcount; ++i)
        if (!deserialize_question_(packet, cursor))
            return false;
    for (i32 i = 0; i < header.ancount; ++i)
        if (!deserialize_rr_(answers, packet, cursor))
            return false;
    for (i32 i = 0; i < header.nscount; ++i)
        if (!deserialize_rr_(authorities, packet, cursor))
            return false;
    for (i32 i = 0; i < header.arcount; ++i)
        if (!deserialize_rr_(additional, packet, cursor))
            return false;
    
    return true;
}

bool
Message::deserialize_header_(
    const std::vector<u8>& packet,
    size_t& cursor
) {
    if (bound_check(cursor, Header::HEADER_SZ, packet.size()))
        return false;

    read_u16(header.id, packet, cursor);
    read_u16(header.flags, packet, cursor);
    read_u16(header.qdcount, packet, cursor);
    read_u16(header.ancount, packet, cursor);
    read_u16(header.nscount, packet, cursor);
    read_u16(header.arcount, packet, cursor);

    // std::memcpy(&header, packet.data(), Header::HEADER_SZ);
    // header.id = ntohs(header.id);
    // header.flags = ntohs(header.flags);
    // header.qdcount = ntohs(header.qdcount);
    // header.ancount = ntohs(header.ancount);
    // header.nscount = ntohs(header.nscount);
    // header.arcount = ntohs(header.arcount);
    // cursor += Header::HEADER_SZ;

    return true;
}

bool
Message::deserialize_question_(
    const std::vector<u8>& packet,
    size_t& cursor
) {
    Question q;

    if (!deserialize_dn_(q.qname, packet, cursor))
        return false;
    
    if (bound_check(cursor, 4, packet.size()))
        return false;
    read_u16(q.type, packet, cursor);
    read_u16(q.klass, packet, cursor);
    
    questions.push_back(std::move(q));

    return true;
}

bool
Message::deserialize_rr_(
    std::vector<ResourceRecord>& v,
    const std::vector<u8> packet, size_t& cursor
) {
    ResourceRecord rr;
    if (!deserialize_dn_(rr.name, packet, cursor))
        return false;

    if (bound_check(cursor, 10, packet.size()))
        return false;

    read_u16(rr.type, packet, cursor);
    read_u16(rr.klass, packet, cursor);
    read_u32(rr.ttl, packet, cursor);
    read_u16(rr.rdlength, packet, cursor);

    switch (rr.type) {
        case RRType::NS: [[fallthrough]];
        case RRType::CNAME: [[fallthrough]];
        case RRType::PTR:
            if (!deserialize_dn_(rr.rdata, packet, cursor))
                return false;
            rr.rdlength = static_cast<u16>(rr.rdata.size());
            break;
        case RRType::A:
            if (bound_check(cursor, 4, packet.size()))
                return false;
            rr.rdata.assign(packet.data() + cursor, packet.data() + cursor + 4);
            cursor += 4;
            break;
        case RRType::AAAA:
            if (bound_check(cursor, 16, packet.size()))
                return false;
            rr.rdata.assign(packet.data() + cursor, packet.data() + cursor + 16);
            cursor += 16;
            break;
        case RRType::OPT:
            for (i32 i = 0; i < rr.rdlength; ) {
                if (bound_check(cursor, 4, packet.size()))
                    return false;

                u16 opt_code = (packet[cursor] << 8) | packet[cursor + 1];
                cursor += 2;
                rr.rdata.push_back(static_cast<char>(opt_code >> 8));
                rr.rdata.push_back(static_cast<char>(opt_code & 0xFF));

                u16 opt_len = (packet[cursor] << 8) | packet[cursor + 1];
                cursor += 2;
                rr.rdata.push_back(static_cast<char>(opt_len >> 8));
                rr.rdata.push_back(static_cast<char>(opt_len & 0xFF));
                
                if (bound_check(cursor, opt_len, packet.size()))
                    return false;

                for (i32 j = 0; j < opt_len; ++j)
                    rr.rdata.push_back(static_cast<char>(packet[cursor++]));
                i += 4 + opt_len;
            }
            break;
        case RRType::SOA:
            if (!deserialize_dn_(rr.rdata, packet, cursor))
                return false;
            if (!deserialize_dn_(rr.rdata, packet, cursor))
                return false;
            if (bound_check(cursor, 20, packet.size()))
                return false;
            rr.rdata.resize(rr.rdata.size() + 20);
            std::memcpy(
                rr.rdata.data() + rr.rdata.size() - 20,
                packet.data() + cursor,
                20
            );
            cursor += 20;
            rr.rdlength = static_cast<u16>(rr.rdata.size());
            break;
        case RRType::MX:
            if (bound_check(cursor, 2, packet.size()))
                return false;
            rr.rdata.reserve(rr.rdlength); rr.rdata.resize(2);
            std::memcpy(rr.rdata.data(), packet.data() + cursor, 2);
            cursor += 2;
            if (!deserialize_dn_(rr.rdata, packet, cursor))
                return false;
            rr.rdlength = static_cast<u16>(rr.rdata.size());
            break;
        case RRType::TXT: {
            rr.rdata.resize(rr.rdlength);
            size_t consumed = 0;
            while (consumed < rr.rdlength) {
                if (bound_check(cursor, 1, packet.size()))
                    return false;
                u8 len = packet[cursor++];
                if (bound_check(consumed, 1, rr.rdata.size()))
                    return false;
                rr.rdata[consumed++] = len;
                if (bound_check(cursor, len, packet.size()))
                    return false;
                if (bound_check(consumed, len, rr.rdata.size()))
                    return false;
                std::memcpy(rr.rdata.data() + consumed, packet.data() + cursor, len);
                consumed += len, cursor += len;
            }
            if (consumed != rr.rdlength) {
                std::cerr << "malformed txt packet\n";
                return false;
            }
            break;
        }
        case RRType::SRV:
            rr.rdata.resize(6);
            if (!bound_check(cursor, 6, packet.size()))
                return false;
            std::memcpy(rr.rdata.data(), packet.data() + cursor, 6);
            cursor += 6;
            if (!deserialize_dn_(rr.rdata, packet, cursor))
                return false;
            rr.rdlength = static_cast<u16>(rr.rdata.size());
            break;
        default:
            std::cerr
            << "rr type "
            << static_cast<u16>(rr.type)
            << " to be implemented.\n";
            cursor += rr.rdlength;
            break;
    }

    v.push_back(std::move(rr));
    return true;
}

bool
Message::deserialize_dn_(
    std::vector<u8>& v,
    const std::vector<u8>& packet,
    size_t& cursor
) {
    while (true) {
        if (bound_check(cursor, 1, packet.size()))
            return false;
        u8 len = packet[cursor];

        if (len == 0) {
            v.push_back('\0');
            break;
        }
        if (len > 63)
            break;

        v.push_back(static_cast<char>(len));
        ++cursor;

        if (bound_check(cursor, len, packet.size()))
            return false;

        while (len--)
            v.push_back(static_cast<char>(packet[cursor++]));
    }
    i32 max_jmp = 20;
    size_t cur = cursor;

    if (bound_check(cursor, 1, packet.size()))
        return false;

    if (packet[cursor] != 0) {
        while (true) {
            if (bound_check(cursor, 1, packet.size()))
                return false;
            u8 byte1 = packet[cursor++];
            if (byte1 == 0) {
                v.push_back('\0');
                break;
            }
            if (byte1 > 63) {
                if (bound_check(cursor, 1, packet.size()))
                    return false;
                u8 byte2 = packet[cursor++];
                byte1 &= 0x3F; // 0b00111111
                u16 ptr = (static_cast<u16>(byte1) << 8) | byte2;
                cursor = ptr;
                if (--max_jmp == 0)
                    return false;
                continue;
            }
            v.push_back(static_cast<char>(byte1));
            if (bound_check(cursor, byte1, packet.size()))
                return false;
            while (byte1--)
                v.push_back(static_cast<char>(packet[cursor++]));
        }
        cursor = cur + 2;
    } else
        cursor = cur + 1;
    return true;
}
