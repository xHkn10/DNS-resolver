#pragma once

#include <chrono>
#include <climits>
#include <iostream>
#include <array>
#include <atomic>

using SC = std::chrono::steady_clock;
using ms = std::chrono::microseconds;

enum class Metric : size_t {
    parse_msg,
    await_send,
    await_rcv,
    cli_resolve_total_udp,
    cli_resolve_total_tcp,
    cli_resolve_total_https,
    cli_resolve_total_tls,
    COUNT
};

struct Stats {
    std::atomic<long long> min{LLONG_MAX};
    std::atomic<long long> max{LLONG_MIN};
    std::atomic<long long> sum{0};
    std::atomic<long long> count{0};

    void update(long long val) {
        long long current_min = min.load();
        while (val < current_min && !min.compare_exchange_weak(current_min, val));
        
        long long current_max = max.load();
        while (val > current_max && !max.compare_exchange_weak(current_max, val));

        sum += val;
        count++;
    }
};

inline std::array<Stats, static_cast<size_t>(Metric::COUNT)> global_metrics;

struct ScopedMeasure {
    Metric m;
    SC::time_point start;

    ScopedMeasure(Metric m) : m(m), start(SC::now()) {}
    
    ~ScopedMeasure() {
        auto end = SC::now();
        auto elapsed = std::chrono::duration_cast<ms>(end - start).count();
        global_metrics[static_cast<size_t>(m)].update(elapsed);
    }
};

inline void print_metric(const char* label, Metric m) {
    auto& s = global_metrics[static_cast<size_t>(m)];
    long long cnt = s.count.load();
    if (cnt > 0) {
        std::cout << label << " (in milliseconds):\n";
        std::cout << "Min: " << s.min.load() / 1000 << "\n";
        std::cout << "Max: " << s.max.load() / 1000 << "\n";
        std::cout << "Avg: " << (long double)s.sum.load() / cnt / 1000 << "\n";
    }
}

inline void print_statistics() {
    print_metric("UDP", Metric::cli_resolve_total_udp);
    print_metric("TCP", Metric::cli_resolve_total_tcp);
}
