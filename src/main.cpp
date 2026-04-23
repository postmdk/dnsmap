#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <unistd.h>

#include "ip_manager.hpp"
#include "dns_processor.hpp"

using namespace std;

void print_usage(char* prog_name) {
    cout << "Usage: " << prog_name << " [-a listen_addr] [-p port] [-u upstream_ip] [-r fake_range] [-d]" << endl;
    cout << "Options:" << endl;
    cout << "  -a <addr>      Address to listen on (default: 0.0.0.0)" << endl;
    cout << "  -p <port>      Port to listen on (default: 53)" << endl;
    cout << "  -u <ip>        Upstream DNS server (default: 9.9.9.10)" << endl;
    cout << "  -r <cidr>      Fake IP range (default: 10.64.0.0/15)" << endl;
    cout << "  -d             Enable verbose debug logging" << endl;
}

int main(int argc, char** argv) {
    string listen_ip = "0.0.0.0";
    int port = 53;
    string upstream_ip = "9.9.9.10";
    string range = "10.64.0.0/15";
    bool debug_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "a:p:u:r:dh")) != -1) {
        switch (opt) {
            case 'a': listen_ip = optarg; break;
            case 'p': port = stoi(optarg); break;
            case 'u': upstream_ip = optarg; break;
            case 'r': range = optarg; break;
            case 'd': debug_mode = true; break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    try {
        // Init manager IP (it will automatically load the old rules from iptables/nftables)
        IPManager ip_manager(range, debug_mode);

        // Create UDP socket of server
        int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_sock < 0) {
            perror("[ ERROR ]: Socket creation failed");
            return 1;
        }

        int optval = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, listen_ip.c_str(), &addr.sin_addr);

        if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("[ ERROR ]: Bind failed (try sudo or setcap)");
            return 1;
        }

        // Preparing the upstream address
        struct sockaddr_in upstream_addr = {};
        upstream_addr.sin_family = AF_INET;
        upstream_addr.sin_port = htons(53);
        inet_pton(AF_INET, upstream_ip.c_str(), &upstream_addr.sin_addr);

        cout << "--- DNSMap started ---" << endl;
        cout << "Listening on: " << listen_ip << ":" << port << endl;
        cout << "Upstream DNS: " << upstream_ip << endl;
        cout << "Fake Range  : " << range << endl;
        if (debug_mode) cout << "Debug Mode  : Enabled" << endl;
        cout << "----------------------" << endl;

        while (true) {
            uint8_t buffer[4096];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            ssize_t n = recvfrom(server_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
            if (n <= 0) continue;

            if (debug_mode) {
                char c_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, c_ip, INET_ADDRSTRLEN);
                cout << "[ DEBUG ]: Request from " << c_ip << endl;
            }

            // Create a temporary socket for communication with upstream
            int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
            sendto(upstream_sock, buffer, n, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
            
            uint8_t res_buffer[4096];
            ssize_t rn = recv(upstream_sock, res_buffer, sizeof(res_buffer), 0);
            close(upstream_sock);

            if (rn > 0) {
                uint8_t* out_pkt = nullptr;
                size_t out_len = 0;

                // call the processing logic from dns_processor.cpp
                process_packet(out_pkt, out_len, res_buffer, rn, ip_manager, debug_mode);

                if (out_pkt) {
                    sendto(server_sock, out_pkt, out_len, 0, (struct sockaddr*)&client_addr, client_len);
                    free(out_pkt); // ldns allocates memory via malloc in pkt2wire
                } else {
                    // Если обработка не удалась, прокидываем оригинальный ответ
                    sendto(server_sock, res_buffer, rn, 0, (struct sockaddr*)&client_addr, client_len);
                }
            }
        }
    } catch (const exception& e) {
        cerr << "[ FATAL ]: " << e.what() << endl;
        return 1;
    }

    return 0;
}
