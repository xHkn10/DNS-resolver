#pragma once

#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <vector>

class Message;

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using i32 = std::int32_t;
using std::size_t;

constexpr u16 DNS_PORT = 53;

enum class DNSClass : u16 {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255
};

enum class RRType : u16 {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41
};

enum class QType : u16 {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    ANY = 255
};

enum class RCode : u8 {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5
};

struct Header {
    u16 id{};
    u16 flags{};
    u16 qdcount{};
    u16 ancount{};
    u16 nscount{};
    u16 arcount{};
    static constexpr size_t HEADER_SZ = 12;
    inline RCode get_err_code() const {return static_cast<RCode>(flags & 0xF);}
    inline bool is_authoritative() const {return flags & 0x0400;}
    inline bool is_rd() const {return flags & 0x0100;}
    inline bool is_tc() const {return flags & 0x0200;}
    inline void set_qr_bit() {flags |= 0x8000;}
    inline void clear_qr_bit() {flags &= 0x7FFF;}
    inline void set_aa_bit() {flags |= 0x0400;}
    inline void clear_aa_bit() {flags &= 0xFBFF;}
    inline void set_tc_bit() {flags |= 0x0200;}
    inline void clear_tc_bit() {flags &= 0xFDFF;}
    inline void set_rd_bit() {flags |= 0x0100;}
    inline void clear_rd_bit() {flags &= 0xFEFF;}
    inline void set_ra_bit() {flags |= 0x0080;}
    inline void clear_ra_bit() {flags &= 0xFF7F;}
    inline void set_errcode(RCode code) {(flags &= 0xFFF0) |= static_cast<u16>(code);}
} __attribute__((packed));

static_assert(
    Header::HEADER_SZ == sizeof(Header),
    "Something went wrong in header size\n"
);

struct Question {
    std::vector<u8> qname;
    QType type{};
    DNSClass klass{};
};

struct ResourceRecord {
    std::vector<u8> name;
    RRType type{};
    DNSClass klass{}; // udp payload sz in edns
    u32 ttl{};     // extended rcode (8 bits), version (8 bits), flags (16 bits) in edns
    u16 rdlength{};
    std::vector<u8> rdata;
};

struct ClientContext {
    int id;
    u16 max_payload = 512;
    bool uses_edns = false;
    bool wants_dnssec = false;
    socklen_t addr_len;
    sockaddr_in addr;
};
