#ifndef IP_MANAGER_HPP
#define IP_MANAGER_HPP

#include <string>
#include <deque>
#include <map>
#include <cstdint>
#include <nftables/libnftables.h>

class IPManager {
public:
    IPManager(const std::string& cidr, bool debug_mode = false);
    ~IPManager();

    uint32_t get_or_create(uint32_t real_ip);

private:
    bool debug;
    std::string base_ip_str;
    int prefix_len;
    struct nft_ctx *nft;
    std::string pool_cidr;

    std::deque<uint32_t> free_ips;
    std::map<uint32_t, uint32_t> real_to_fake;

    void parse_cidr(const std::string& cidr);
    void sync_with_kernel();
    void setup_base_structure();
    bool nft_run(const std::string& json_cmd);
};

#endif