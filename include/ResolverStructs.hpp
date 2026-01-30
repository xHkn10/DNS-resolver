#pragma once

#include "types.hpp"
#include "Message.hpp"

enum class ResolverStatus {
    Success,         // Found an answer OR authoritative proof of non-existence
    LoopDetected,    // Fatal: CNAME loop or depth exceeded
    NoCandidates,    // Fatal: Checked all NS records and all failed
    InternalError    // Fatal: Serialization failed, etc.
};

struct ResolverResult {
    ResolverStatus status;
    RCode code;
    Message msg;
    explicit operator bool() {
        return status == ResolverStatus::Success;
    }
};