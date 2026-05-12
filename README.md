
## DNSMap-C++ working via nftables API for Linux
DNS proxy server in C++ for dynamic mapping IP.
optimized for Linux network environments.
## Main functions

* **Dynamic NAT**: Intercepts `A`-records DNS and replaces real IPs with "fake" ones from a specified pool.
* **Netfilter Control**: `nftables` (DNAT) create
```
table ip dnsmap {
	map fake_to_real {
		type ipv4_addr : ipv4_addr
		elements = { ... }
chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr <IP Range> dnat to ip daddr map @fake_to_real
	}
		

```
* **IPv6 Blocking**: Blocks `AAAA` and `HTTPS` records, forcing the use of IPv4.
* **State Recovery**: On startup, it reads the current rules from the system, restoring the mapping table.
* **Debug Mode**: Detailed logging of network operations and DNS packet manipulation.
* **Arguments**: -a (address), -p (port), -u (upstream), -r (range), -w (workers).
* **-d**: Run in a demonize
* **-v**: Enables verbose output.
## Dependencies

* **Library**: `libldns3t64 libnftables1`
* **Compiler**: GCC with C++17
* **Permissions**: `CAP_NET_ADMIN` to manage the firewall and `CAP_NET_BIND_SERVICE` to work on port 53.

In Debian/Ubuntu installing develop dependencies for build
```bash
sudo apt install libldns-dev libnftables-dev nlohmann-json3-dev
```
In Debian/Ubuntu installing dependencies for work
```bash 
sudo apt install libldns3 libnftables1
```
## Build
```bash
make
```
