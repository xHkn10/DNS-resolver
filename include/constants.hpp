#pragma once

#include "types.hpp"
#include <array>

namespace dns::roots {
    #define ROOT_NAME(c) { \
        1, c, \
        12, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', \
        3, 'n', 'e', 't', 0 \
    }

    inline const ResourceRecord a{ROOT_NAME('a'), RRType::A, DNSClass::IN, 3600000, 4, {198, 41, 0, 4}};
    inline const ResourceRecord b{ROOT_NAME('b'), RRType::A, DNSClass::IN, 3600000, 4, {199, 9, 14, 201}};
    inline const ResourceRecord c{ROOT_NAME('c'), RRType::A, DNSClass::IN, 3600000, 4, {192, 33, 4, 12}};
    inline const ResourceRecord d{ROOT_NAME('d'), RRType::A, DNSClass::IN, 3600000, 4, {199, 7, 91, 13}};
    inline const ResourceRecord e{ROOT_NAME('e'), RRType::A, DNSClass::IN, 3600000, 4, {192, 203, 230, 10}};
    inline const ResourceRecord f{ROOT_NAME('f'), RRType::A, DNSClass::IN, 3600000, 4, {192, 5, 5, 241}};
    inline const ResourceRecord g{ROOT_NAME('g'), RRType::A, DNSClass::IN, 3600000, 4, {192, 112, 36, 4}};
    inline const ResourceRecord h{ROOT_NAME('h'), RRType::A, DNSClass::IN, 3600000, 4, {198, 97, 190, 53}};
    inline const ResourceRecord i{ROOT_NAME('i'), RRType::A, DNSClass::IN, 3600000, 4, {192, 36, 148, 17}};
    inline const ResourceRecord j{ROOT_NAME('j'), RRType::A, DNSClass::IN, 3600000, 4, {192, 58, 128, 30}};
    inline const ResourceRecord k{ROOT_NAME('k'), RRType::A, DNSClass::IN, 3600000, 4, {193, 0, 14, 129}};
    inline const ResourceRecord l{ROOT_NAME('l'), RRType::A, DNSClass::IN, 3600000, 4, {199, 7, 83, 42}};
    inline const ResourceRecord m{ROOT_NAME('m'), RRType::A, DNSClass::IN, 3600000, 4, {202, 12, 27, 33}};

    #undef ROOT_NAME

    inline const std::array ALL{a, b, c, d, e, f, g, h, i, j, k, l, m};
}
