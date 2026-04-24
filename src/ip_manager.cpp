#include "ip_manager.hpp"
#include <vector>
#include <arpa/inet.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <syslog.h>

using namespace std;

IPManager::IPManager(const string& cidr, bool debug_mode) : debug(debug_mode) {
    parse_cidr(cidr);
    load_existing_mappings();
}

void IPManager::exec_command(const string& cmd) {
    if (debug) {
        syslog(LOG_DEBUG, "[ DEBUG ]: System call: %s", cmd.c_str());
    }
    if (system(cmd.c_str()) != 0) {
        syslog(LOG_ERR, "[ ERROR ]: Failed to execute: %s", cmd.c_str());
    }
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

    // Exclude the network address and broadcast
    for (uint32_t i = 1; i < num_hosts - 1; ++i) {
        free_ips.push_back(start_ip + i);
    }
    
    if (debug) {
        syslog(LOG_DEBUG, "[ DEBUG ]: IP pool initialized with %zu addresses.", free_ips.size());
    }
}

void IPManager::load_existing_mappings() {
    string cmd;
#ifdef USE_NFTABLES
    cmd = "nft list table ip nat | grep 'dnat to'"; 
#else
    cmd = "iptables -w -t nat -nL PREROUTING | awk '{if (NR<3) {next}; sub(/to:/, \"\", $6); print $5, $6}'";
#endif

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return;

    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) {
        char f_s[INET_ADDRSTRLEN], r_s[INET_ADDRSTRLEN];
        if (sscanf(buf, "%15s %15s", f_s, r_s) == 2) {
            uint32_t f_ip = ntohl(inet_addr(f_s));
            uint32_t r_ip = ntohl(inet_addr(r_s));
            real_to_fake[r_ip] = f_ip;
            
            auto it = find(free_ips.begin(), free_ips.end(), f_ip);
            if (it != free_ips.end()) {
                free_ips.erase(it);
            }
            
            if (debug) {
                syslog(LOG_DEBUG, "[ DEBUG ]: Restored %s -> %s", f_s, r_s);
            }
        }
    }
    pclose(pipe);
}

uint32_t IPManager::get_or_create(uint32_t real_ip) {
    if (real_to_fake.count(real_ip)) return real_to_fake[real_ip];

    if (free_ips.empty()) {
        syslog(LOG_WARNING, "[ WARNING ]: IP pool exhausted!");
        /* * TODO: Implement LRU (Least Recently Used) expiration logic here.
         * When the pool is exhausted, we should evict the oldest mapping
         * and remove its corresponding iptables/nftables rule to free up space.
         */
        return 0;
    }

    uint32_t fake_ip = free_ips.front();
    free_ips.pop_front();
    real_to_fake[real_ip] = fake_ip;

    char f_s[INET_ADDRSTRLEN];
    char r_s[INET_ADDRSTRLEN];
    struct in_addr f_addr, r_addr;
    
    f_addr.s_addr = htonl(fake_ip);
    r_addr.s_addr = htonl(real_ip);

    inet_ntop(AF_INET, &f_addr, f_s, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &r_addr, r_s, INET_ADDRSTRLEN);

    string cmd;
#ifdef USE_NFTABLES
    cmd = "nft add rule ip nat PREROUTING ip daddr " + string(f_s) + " dnat to " + string(r_s);
#else
    cmd = "iptables -w -t nat -A PREROUTING -d " + string(f_s) + " -j DNAT --to " + string(r_s);
#endif

    exec_command(cmd);
    
    if (debug) {
        syslog(LOG_INFO, "[  NEW  ]: Mapping created: %s -> %s", f_s, r_s);
    }

    return fake_ip;
}
