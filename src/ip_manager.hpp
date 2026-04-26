#ifndef IP_MANAGER_HPP
#define IP_MANAGER_HPP

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <cstdint>
#include <nftables/libnftables.h> // Required to work with the API

class IPManager {
public:
    IPManager(const std::string& cidr, bool debug_mode = false);
    ~IPManager();

    uint32_t get_or_create(uint32_t real_ip);

private:
    bool debug;
    struct nft_ctx *nft;

    std::deque<uint32_t> free_ips;
    std::map<uint32_t, uint32_t> real_to_fake;

    void parse_cidr(const std::string& cidr);
    void setup_base_structure(); // The name must match .cpp
    void load_existing_mappings();

    bool nft_run(const std::string& json_cmd);
};

#endif