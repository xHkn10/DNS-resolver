#pragma once

#include "types.hpp"
#include <optional>
#include <string>
#include <vector>

class Message {
public:
    Header header;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additional;

    Message() = default;

    std::optional<std::vector<u8>> serialize() const;
    static std::optional<Message> deserialize(const std::vector<u8>& packet);
    
    Message from_questions() const;
    
    void put_random_id();

    bool has_glue() const;

    void put_edns_opt();
    const ResourceRecord* get_edns_opt_record() const;
    void assign_edns_related_fields(ClientContext& cli) const;

    size_t size() const;

    void truncate_msg(size_t max_sz);
    void strip_sections();
    
    static std::string rdata_to_string(const ResourceRecord& rr);

private:
    bool deserialize_all_(const std::vector<u8>& packet);
    bool deserialize_header_(const std::vector<u8>& packet, size_t& cursor);
    bool deserialize_question_(const std::vector<u8>& packet, size_t& cursor);
    bool deserialize_rr_(
        std::vector<ResourceRecord>& v,
        const std::vector<u8> packet,
        size_t& cursor
    );
    bool deserialize_dn_(
        std::vector<u8>& s,
        const std::vector<u8>& packet,
        size_t& cursor
    );
};
