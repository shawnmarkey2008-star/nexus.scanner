# Nexus Scanner

A simple Python network scanner for my personal **Nexus (Network for Experimentation Utility and Storage)** homelab.

Built to practice network discovery, TCP connections, multithreading, and CSV reporting. It provides basic discovery and port checks; it does not offer Nmap's full feature set.

## Features

- Discover IPv4 hosts through ping replies or successful TCP connections.
- Check 14 common TCP ports, including SSH, HTTP, HTTPS, SMB, RDP, Proxmox, Jellyfin, and Home Assistant.
- Attempt reverse DNS hostname lookup.
- Scan multiple hosts concurrently.
- Save results to CSV, sorted by IP address.
- Configure the subnet, TCP timeout, worker count, and output filename.

## Requirements

- Python 3.6 or newer; a maintained Python 3 release is recommended.
- No third-party Python packages are required.
- The system `ping` command for ping-based discovery. TCP checks still work if ping is unavailable.

The script includes Windows and Linux ping command forms. macOS uses different `ping -W` timeout units, so ping discovery may miss hosts there; TCP discovery remains available. This initial upload preserves the original script.

## Get started

Download this repository using **Code → Download ZIP** and extract it, or clone it:

```sh
git clone https://github.com/shawnmarkey2008-star/nexus.scanner.git
cd nexus.scanner
```

From the project folder on Windows:

```powershell
python scanner.py --network 192.168.1.0/24
```

On Linux or macOS:

```sh
python3 scanner.py --network 192.168.1.0/24
```

Replace the example subnet with the network you intend to scan. Only scan networks you own or have permission to test.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--network` | `192.168.1.0/24` | IPv4 subnet; at most 256 total addresses |
| `--timeout` | `0.4` | TCP connection timeout in seconds, from 0.1 to 5 |
| `--workers` | `32` | Concurrent hosts, from 1 to 64 |
| `--output` | `nexus_results.csv` | CSV output path |

Example with a smaller subnet and custom settings:

```sh
python scanner.py --network 192.168.1.0/28 --timeout 1 --workers 8 --output lab_scan.csv
```

Show help with `python scanner.py --help`.

## Results

The CSV contains **IP Address**, **Hostname**, **Ping Response**, and **Open TCP Ports**. It is written to the current working directory unless another path is supplied. An existing file at that path is overwritten.

CSV reports are ignored by Git to help keep discovered device information local.

## Customize ports

Edit the `DEFAULT_PORTS` dictionary in `scanner.py`. Labels describe typical services for each port; the scanner does not verify which application is actually running.

## Limitations

- TCP and IPv4 only; no UDP scanning, OS detection, or vulnerability checks.
- Hosts that block ping and have none of the checked TCP ports open will not appear.
- Firewalls, VLAN routing, and client isolation affect visibility.
- Reverse DNS may return `Unknown` or take additional time.
- The TCP timeout does not control ping or DNS lookup time.

## Validation

The initial GitHub upload was checked for Python syntax and command-line help. Live discovery on the homelab and behavior on each operating system were not retested during upload.
