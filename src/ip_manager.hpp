#pragma once
#include <string>
#include <deque>
#include <unordered_map>
#include <stdint.h>

class IPManager {
private:
    std::deque<uint32_t> free_ips;
    std::unordered_map<uint32_t, uint32_t> real_to_fake;
    bool debug;

    void exec_command(const std::string& cmd);
    void parse_cidr(const std::string& cidr);
    void load_existing_mappings();

public:
    IPManager(const std::string& cidr, bool debug_mode = false);
    uint32_t get_or_create(uint32_t real_ip);
};
