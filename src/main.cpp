#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>

#include "ip_manager.hpp"
#include "dns_processor.hpp"

using namespace std;

const string VERSION = "1.0.1";

// Global variable for loop control
bool keep_running = true;

void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            syslog(LOG_INFO, "Termination signal received. Shutting down...");
            keep_running = false;
            break;
    }
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); 

    if (setsid() < 0) exit(EXIT_FAILURE); 

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") < 0) exit(EXIT_FAILURE);

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    openlog("dnsmap", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void print_usage(char* prog_name) {
    cout << "Usage: " << prog_name << " [-a listen_addr] [-p port] [-u upstream_ip] [-r fake_range] [-d] [-v] [--version]" << endl;
    cout << "Options:" << endl;
    cout << "  -a <addr>      Address to listen on (default: 0.0.0.0)" << endl;
    cout << "  -p <port>      Port to listen on (default: 53)" << endl;
    cout << "  -u <ip>        Upstream DNS server (default: 9.9.9.10)" << endl;
    cout << "  -r <cidr>      Fake IP range (default: 10.64.0.0/15)" << endl;
    cout << "  -d             Run as daemon (background)" << endl;
    cout << "  -v             Enable verbose debug logging" << endl;
    cout << "  --version      Show version information" << endl;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "--version") {
            cout << "DNSMap version " << VERSION << endl;
            return 0;
        }
    }

    string listen_ip = "0.0.0.0";
    int port = 53;
    string upstream_ip = "9.9.9.10";
    string range = "10.64.0.0/15";
    bool debug_mode = false;
    bool should_daemonize = false;

    int opt;
    while ((opt = getopt(argc, argv, "a:p:u:r:dvh")) != -1) {
        switch (opt) {
            case 'a': listen_ip = optarg; break;
            case 'p': port = stoi(optarg); break;
            case 'u': upstream_ip = optarg; break;
            case 'r': range = optarg; break;
            case 'd': should_daemonize = true; break;
            case 'v': debug_mode = true; break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (should_daemonize) {
        daemonize();
    } else {
        // if in foreground, logs to stderr (LOG_PERROR)
        openlog("dnsmap", LOG_PID | LOG_PERROR, LOG_USER);
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    try {
        IPManager ip_manager(range, debug_mode);

        int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_sock < 0) {
            syslog(LOG_ERR, "Socket creation failed: %m");
            return 1;
        }

        int optval = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, listen_ip.c_str(), &addr.sin_addr);

        if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "Bind failed on %s:%d: %m", listen_ip.c_str(), port);
            return 1;
        }

        struct sockaddr_in upstream_addr = {};
        upstream_addr.sin_family = AF_INET;
        upstream_addr.sin_port = htons(53);
        inet_pton(AF_INET, upstream_ip.c_str(), &upstream_addr.sin_addr);

        syslog(LOG_NOTICE, "DNSMap started. Listening: %s:%d, Upstream: %s", 
               listen_ip.c_str(), port, upstream_ip.c_str());

        while (keep_running) {
            uint8_t buffer[4096];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            ssize_t n = recvfrom(server_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
            if (n <= 0) continue;

            if (debug_mode) {
                char c_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, c_ip, INET_ADDRSTRLEN);
                syslog(LOG_DEBUG, "Request from %s", c_ip);
            }

            int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (upstream_sock < 0) {
                syslog(LOG_WARNING, "Failed to create upstream socket");
                continue;
            }

            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            sendto(upstream_sock, buffer, n, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
            
            uint8_t res_buffer[4096];
            ssize_t rn = recv(upstream_sock, res_buffer, sizeof(res_buffer), 0);
            close(upstream_sock);

            if (rn > 0) {
                uint8_t* out_pkt = nullptr;
                size_t out_len = 0;

                process_packet(out_pkt, out_len, res_buffer, rn, ip_manager, debug_mode);

                if (out_pkt) {
                    sendto(server_sock, out_pkt, out_len, 0, (struct sockaddr*)&client_addr, client_len);
                    free(out_pkt);
                } else {
                    sendto(server_sock, res_buffer, rn, 0, (struct sockaddr*)&client_addr, client_len);
                }
            }
        }

        close(server_sock);
        syslog(LOG_NOTICE, "DNSMap stopped gracefully");

    } catch (const exception& e) {
        syslog(LOG_CRIT, "Fatal exception: %s", e.what());
        closelog();
        return 1;
    }

    closelog();
    return 0;
}