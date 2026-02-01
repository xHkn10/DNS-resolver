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
    static constexpr u16 MASK_QR = 0x8000;
    static constexpr u16 MASK_AA = 0x0400;
    static constexpr u16 MASK_TC = 0x0200;
    static constexpr u16 MASK_RD = 0x0100;
    static constexpr u16 MASK_RA = 0x0080;
    static constexpr u16 MASK_RCODE = 0x000F;

    inline RCode get_err_code() const {return static_cast<RCode>(flags & MASK_RCODE);}
    inline void set_errcode(RCode code) {(flags &= ~MASK_RCODE) |= static_cast<u16>(code);}

    inline bool is_authoritative() const {return flags & MASK_AA;}
    inline bool is_rd() const {return flags & MASK_RD;}
    inline bool is_tc() const {return flags & MASK_TC;}

    inline void set_qr_bit() {flags |= MASK_QR;}
    inline void set_aa_bit() {flags |= MASK_AA;}
    inline void set_tc_bit() {flags |= MASK_TC;}
    inline void set_ra_bit() {flags |= MASK_RA;}
    inline void set_rd_bit() {flags |= MASK_RD;}

    inline void clear_qr_bit() {flags &= ~MASK_QR;}
    inline void clear_aa_bit() {flags &= ~MASK_AA;}
    inline void clear_tc_bit() {flags &= ~MASK_TC;}
    inline void clear_rd_bit() {flags &= ~MASK_RD;}
    inline void clear_ra_bit() {flags &= ~MASK_RA;}
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

enum class DnsMode : u8 {
    UDP,
    TCP,
    DoT, // to be imp
    DoH  // to be imp
};

struct ClientContext {
    Question cli_q;
    int id;
    u16 max_payload = 0xFFFFU;
    bool uses_edns = false;
    DnsMode mode;
};
