import socket
import subprocess
import platform
import ipaddress
import csv
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
 
# PROJECT NEXUS - PYTHON NETWORK SCANNER
DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8006: "Proxmox",
    8080: "HTTP Alternate",
    8096: "Jellyfin",
    8123: "Home Assistant",
    25565: "Minecraft Java"
}
 
 
def ping_host(ip):
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=3
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
 
 
def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
 
 
def get_hostname(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"
 
 
def scan_host(ip, ports, timeout):
    ping_responded = ping_host(ip)
    open_ports = []
    for port in ports:
        if scan_port(ip, port, timeout):
            open_ports.append(port)
    if not ping_responded and not open_ports:
        return None
    return {
        "ip": ip,
        "hostname": get_hostname(ip),
        "ping": ping_responded,
        "open_ports": open_ports
    }
 
 
def save_results(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Hostname", "Ping Response", "Open TCP Ports"])
        for host in results:
            writer.writerow([
                host["ip"], host["hostname"], host["ping"],
                ", ".join(str(port) for port in host["open_ports"])
            ])
    print(f"\n[+] Results saved to {filename}")
 
 
def main():
    parser = argparse.ArgumentParser(description="Project Nexus Network Scanner")
    parser.add_argument("--network", default="192.168.1.0/24",
                        help="IPv4 subnet to scan")
    parser.add_argument("--timeout", type=float, default=0.4,
                        help="TCP connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=32,
                        help="Number of concurrent hosts")
    parser.add_argument("--output", default="nexus_results.csv",
                        help="CSV output filename")
    args = parser.parse_args()
 
    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except ValueError:
        parser.error("Invalid network address.")
    if network.version != 4:
        parser.error("Only IPv4 is supported.")
    if network.num_addresses > 256:
        parser.error("Maximum scan size is 256 addresses (/24).")
    if not 0.1 <= args.timeout <= 5:
        parser.error("Timeout must be between 0.1 and 5 seconds.")
    if not 1 <= args.workers <= 64:
        parser.error("Workers must be between 1 and 64.")
 
    targets = [str(ip) for ip in network.hosts()]
    print("\n" + "=" * 52)
    print("           PROJECT NEXUS SCANNER")
    print("=" * 52)
    print(f"Network: {network}")
    print(f"Targets: {len(targets)}")
    print(f"Workers: {args.workers}")
    print(f"TCP Ports: {len(DEFAULT_PORTS)}")
    print("=" * 52)
 
    start_time = time.time()
    results = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_host, ip, DEFAULT_PORTS, args.timeout): ip
            for ip in targets
        }
        for future in as_completed(futures):
            completed += 1
            ip = futures[future]
            try:
                host = future.result()
            except Exception as error:
                print(f"[!] Error scanning {ip}: {error}")
                continue
            if host is not None:
                results.append(host)
                print(f"\n[+] HOST FOUND: {host['ip']}")
                print(f"    Hostname: {host['hostname']}")
                print(f"    Ping: {host['ping']}")
                for port in host["open_ports"]:
                    print(f"    TCP {port}: OPEN ({DEFAULT_PORTS[port]})")
            if completed % 25 == 0:
                print(f"\n[*] Progress: {completed}/{len(targets)}")
 
    results.sort(key=lambda host: ipaddress.ip_address(host["ip"]))
    elapsed = round(time.time() - start_time, 2)
    print("\n" + "=" * 52)
    print("SCAN COMPLETED")
    print("=" * 52)
    print(f"Discovered hosts: {len(results)}")
    print(f"Elapsed time: {elapsed} seconds")
    save_results(results, args.output)
 
 
if __name__ == "__main__":
    main()
