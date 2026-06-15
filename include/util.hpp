#pragma once

#include "types.hpp"
#include "config.hpp"

#include <random>
#include <span>
#include <vector>
#include <iostream>
#include <iomanip>


#ifndef DISABLE_LOG
#define LOG(msg) std::cout << "[LOG] " << msg << std::endl
#else
#define LOG(msg)
#endif

inline std::ostream& operator<<(std::ostream& os, RCode code) {
    switch (code) {
        case RCode::NoError: os << "NoError"; break;
        case RCode::FormErr:  os << "FormErr"; break;
        case RCode::ServFail: os << "ServFail"; break;
        case RCode::NXDomain: os << "NXDomain"; break;
        case RCode::NotImp: os << "NotImp"; break;
        case RCode::Refused: os << "Refused"; break;
        default: os << "Unknown"; break;
    }
    return os;
}


inline std::ostream& operator<<(std::ostream& os, RRType type) {
    switch (type) {
        case RRType::A: os << "A"; break;
        case RRType::NS: os << "NS"; break;
        case RRType::CNAME: os << "CNAME"; break;
        case RRType::SOA: os << "SOA"; break;
        case RRType::PTR: os << "PTR"; break;
        case RRType::MX: os << "MX"; break;
        case RRType::TXT: os << "TXT"; break;
        case RRType::AAAA: os << "AAAA"; break;
        case RRType::SRV: os << "SRV"; break;
        case RRType::OPT: os << "OPT"; break;
        default: os << "UNKOWN TYPE"; break;
    }
    return os;
}

namespace util {
    inline void pretty_print_bytes(const std::vector<u8>& bytes) {
        for (u8 b : bytes) {
            std::cout
            << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(b) << " ";
        }
        std::cout << std::dec << std::endl;
    }
    
    inline void pp_bytes(const std::vector<u8>& bytes) {
        pretty_print_bytes(bytes);
    }

    std::string dn_to_str(const auto& dn) {
        std::string res;
        for (i32 i{0}; ; ) {
            u8 label_len = dn[i++];
            if (label_len == 0)
                break;
            while (label_len--)
                res.push_back(static_cast<char>(dn[i++]));
            res.push_back('.');
        }
        return res;
    }
    
    inline std::string bytes_to_ipv4(const std::vector<u8>& bytes) {
        std::string res;
        for (i32 i = 0; i < 4; ++i) {
            res.append(std::to_string(bytes[i]));
            if (i != 3)
                res.push_back('.');
        }
        return res;
    }

    inline u32 bytes_to_u32(const std::vector<u8>& v) {
        return (
            (static_cast<u32>(v[0]) << 24)
            | (static_cast<u32>(v[1]) << 16)
            | (static_cast<u32>(v[2]) << 8)
            | (static_cast<u32>(v[3]))
        );
    }

    inline auto& seed() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        return gen;
    }

    inline std::vector<u8> normalize(std::span<const u8> str) {
        std::vector<u8> res;
        res.reserve(str.size());
        u8 off = 'A' - 'a';
        for (u8 c : str)
            res.push_back(c - ('A' <= c && c <= 'Z') * off);
        return res;
    }

    template <typename T>
    void shuffle(std::vector<T>& v) {
        std::shuffle(v.begin(), v.end(), seed());
    }
}
