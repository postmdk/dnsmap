#include "ip_manager.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <syslog.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

IPManager::IPManager(const string& cidr, bool debug_mode) : debug(debug_mode) {
    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        syslog(LOG_ERR, "[ CRIT ]: Failed to initialize nftables context");
        exit(EXIT_FAILURE);
    }

    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);

    parse_cidr(cidr);
    setup_base_structure();
    load_existing_mappings();
}

IPManager::~IPManager() {
    if (nft) {
        nft_ctx_free(nft);
    }
}

bool IPManager::nft_run(const string& json_cmd) {
    if (debug) {
        syslog(LOG_DEBUG, "[ DEBUG ]: nft API call: %s", json_cmd.c_str());
    }
    int res = nft_run_cmd_from_buffer(nft, json_cmd.c_str());
    return (res == 0);
}

void IPManager::setup_base_structure() {
    // Initialize a JSON object with the rules structure
    json setup = {
            {"nftables", {
                    {{"add", {{"table", {{"family", "ip"}, {"name", "dnsmap"}}}}}},
                    {{"add", {{"chain", {
                            {"family", "ip"},
                            {"table", "dnsmap"},
                            {"name", "PREROUTING"},
                            {"type", "nat"},
                            {"hook", "prerouting"},
                            {"prio", -100}
                    }}}}}}
            }
    };

// Call nft_run, passing a JSON string dump
nft_run(setup.dump());
}

void IPManager::parse_cidr(const string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == string::npos) return;

    string ip_part = cidr.substr(0, slash);
    int prefix = stoi(cidr.substr(slash + 1));

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part.c_str(), &addr) <= 0) return;

    uint32_t start_ip = ntohl(addr.s_addr);
    uint32_t num_hosts = pow(2, 32 - prefix);

    for (uint32_t i = 1; i < num_hosts - 1; ++i) {
        free_ips.push_back(start_ip + i);
    }
}

void IPManager::load_existing_mappings() {
    nft_ctx_buffer_output(nft);
    string list_cmd = "{\"nftables\":[{\"list\":{\"table\":{\"family\":\"ip\",\"name\":\"dnsmap\"}}}]}";
    nft_run(list_cmd);
    nft_ctx_unbuffer_output(nft);
}

uint32_t IPManager::get_or_create(uint32_t real_ip) {
    if (real_to_fake.count(real_ip)) return real_to_fake[real_ip];

    if (free_ips.empty()) return 0;

    uint32_t fake_ip = free_ips.front();
    free_ips.pop_front();
    real_to_fake[real_ip] = fake_ip;

    char f_s[INET_ADDRSTRLEN], r_s[INET_ADDRSTRLEN];
    struct in_addr f_addr = { .s_addr = htonl(fake_ip) };
    struct in_addr r_addr = { .s_addr = htonl(real_ip) };
    inet_ntop(AF_INET, &f_addr, f_s, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &r_addr, r_s, INET_ADDRSTRLEN);

    json add_rule = {
            {"nftables", {
                    {
                            {"add", {
                                    {"rule", {
                                            {"family", "ip"},
                                            {"table", "dnsmap"},
                                            {"chain", "PREROUTING"},
                                            {"expr", {
                                                    // Expression 1: Payload selector
                                                    {
                                                            {"match", {
                                                                    {"left", {
                                                                            {"payload", {
                                                                                    {"protocol", "ip"},
                                                                                    {"field", "daddr"}
                                                                            }}
                                                                    }},
                                                                    {"op", "=="}, // An explicit statement is often required.
                                                                    {"right", f_s}
                                                            }}
                                                    },
                                                    // Expression 2: action(dnat)
                                                    {
                                                            {"dnat", {
                                                                    {"addr", r_s}
                                                            }}
                                                    }
                                            }}
                                    }}
                            }}
                    }
            }}
    };

    if (nft_run(add_rule.dump())) {
        if (debug) syslog(LOG_INFO, "[  NEW  ]: Mapping created via API: %s -> %s", f_s, r_s);
    }
    return fake_ip;
}