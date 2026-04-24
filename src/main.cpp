#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>

#include "ip_manager.hpp"
#include "dns_processor.hpp"

using namespace std;

#ifndef VERSION
#define VERSION "1.0.1"
#endif

// Глобальная переменная для управления циклом
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
    cout << "Usage: " << prog_name << " [options]" << endl;
    cout << "Options:" << endl;
    cout << "  -a, --listen <addr>    Address to listen on (default: 0.0.0.0)" << endl;
    cout << "  -p, --port <port>      Port to listen on (default: 53)" << endl;
    cout << "  -u, --upstream <ip>    Upstream DNS server (default: 9.9.9.10)" << endl;
    cout << "  -r, --range <cidr>     Fake IP range (default: 10.64.0.0/15)" << endl;
    cout << "  -d, --daemonize        Run as daemon (background)" << endl;
    cout << "  -v, --verbose          Enable verbose debug logging" << endl;
    cout << "  -V, --version          Show version information" << endl;
    cout << "  -h, --help             Show this help message" << endl;
}

int main(int argc, char** argv) {
    string listen_ip = "0.0.0.0";
    int port = 53;
    string upstream_ip = "9.9.9.10";
    string range = "10.64.0.0/15";
    bool debug_mode = false;
    bool should_daemonize = false;

    static struct option long_options[] = {
        {"listen",    required_argument, 0, 'a'},
        {"port",      required_argument, 0, 'p'},
        {"upstream",  required_argument, 0, 'u'},
        {"range",     required_argument, 0, 'r'},
        {"daemonize", no_argument,       0, 'd'},
        {"verbose",   no_argument,       0, 'v'},
        {"version",   no_argument,       0, 'V'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "a:p:u:r:dvhV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a': listen_ip = optarg; break;
            case 'p': port = stoi(optarg); break;
            case 'u': upstream_ip = optarg; break;
            case 'r': range = optarg; break;
            case 'd': should_daemonize = true; break;
            case 'v': debug_mode = true; break;
            case 'V':
                cout << "DNSMap version " << VERSION << endl;
                return 0;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (should_daemonize) {
        daemonize();
    } else {
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

        /* * Set a receive timeout. Without this, recvfrom() would block forever,
         * preventing the daemon from checking 'keep_running' and shutting down 
         * gracefully during systemctl stop.
         */
        struct timeval tv_timeout;
        tv_timeout.tv_sec = 1; 
        tv_timeout.tv_usec = 0;
        setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

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

        syslog(LOG_NOTICE, "DNSMap %s started. Listening: %s:%d", VERSION, listen_ip.c_str(), port);

        while (keep_running) {
            uint8_t buffer[4096];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            ssize_t n = recvfrom(server_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
            
            if (n < 0) {
                // If errno is EAGAIN or EWOULDBLOCK, it's just a timeout, so loop back
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (keep_running) syslog(LOG_ERR, "recvfrom error: %m");
                break;
            }

            if (debug_mode) {
                char c_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, c_ip, INET_ADDRSTRLEN);
                syslog(LOG_DEBUG, "Request from %s", c_ip);
            }

            int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (upstream_sock < 0) continue;

            struct timeval tv_up;
            tv_up.tv_sec = 2;
            tv_up.tv_usec = 0;
            setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_up, sizeof(tv_up));

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
