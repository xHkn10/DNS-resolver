#pragma once

#include "types.hpp"
#include "Message.hpp"

enum class ResolverStatus {
    Success,         // found an answer or NXDOMAIN or NODATA
    LoopDetected,    // CNAME loop or depth exceeded
    NoCandidates,    // checked all NS records and all failed
    InternalError    // serialization failed etc
};

struct ResolverResult {
    ResolverStatus status;
    RCode code;
    Message msg;
    explicit operator bool() {
        return status == ResolverStatus::Success;
    }
};