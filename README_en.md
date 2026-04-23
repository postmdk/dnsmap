
## DNSMap-C++
DNS proxy server in C++ for dynamic mapping IP.
This is a port of the original Python script by ValdikSS https://github.com/valdikss, optimized for Linux network environments.
## Main functions

* **Dynamic NAT**: Intercepts `A`-records DNS and replaces real IPs with "fake" ones from a specified pool.
* **Netfilter Control**: Automatically writes `iptables` or `nftables` (DNAT) rules to transparently redirect traffic.
* **IPv6 Blocking**: Blocks `AAAA` and `HTTPS` records, forcing the use of IPv4.
* **State Recovery**: On startup, it reads the current rules from the system, restoring the mapping table.
* **Debug Mode**: Detailed logging of network operations and DNS packet manipulation.
* **Arguments**: -a (address), -p (port), -u (upstream), -r (range).
* **-f**: -f Run in foreground (don't daemonize)
* **-d**: Enables verbose output.
## Dependencies

For build and working needs:
* **Library ldns**: `libldns-dev`
* **Compiler**: GCC с поддержкой C++17
* **Permissions**: `CAP_NET_ADMIN` to manage the firewall and `CAP_NET_BIND_SERVICE` to work on port 53.

In Debian, Ubuntu installing dependencies:
```bash
sudo apt install libldns-dev
```
## Build
```bash
make
make BACKEND=nftables # nftables
```
