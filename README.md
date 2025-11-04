# torNmap — TCP Connect Scanner over Tor

A lightweight, educational TCP port scanner that operates through the Tor network. This tool is designed for learning and controlled testing environments. **Only use it on systems you own or have explicit permission to test.**

## Overview

torNmap performs TCP connect scans through a local Tor SOCKS5 proxy. Unlike full-featured network scanners like Nmap, torNmap is intentionally limited due to the constraints and architecture of the Tor network.

## Features

- **TCP Connect Scanning**: Basic port scanning via full TCP connection establishment
- **Tor Integration**: Routes all connections through Tor SOCKS5 proxy for anonymity
- **Concurrent Scanning**: Configurable worker threads for parallel port probing
- **URL/Hostname Support**: Can scan both regular hostnames and .onion hidden services
- **Circuit Rotation**: Optional Tor circuit rotation between probes (requires ControlPort)
- **Configurable Timeouts**: Adjustable connection timeouts to handle Tor latency
- **Port Validation**: Built-in limits to prevent abuse (max 1000 ports per scan)
- **Basic Output**: Simple, readable scan results with summary statistics

## Limitations (By Design)

Due to Tor network architecture and scanning best practices, torNmap has the following limitations:

1. **Host Discovery**: No ICMP, UDP, or SCTP probes — only performs direct TCP connection attempts
2. **Scan Techniques**: Limited to basic TCP connect probes — cannot perform SYN, ACK, FIN, Xmas, Null, idle scans, or other advanced scan types
3. **Service Detection**: Does not incorporate detection of services/versions or OS fingerprinting
4. **Firewall Evasion**: Lacks fragmentation, spoofing, decoys, or similar evasion methods
5. **Port Scanning Range**: Limited to 1000 ports maximum per scan to prevent abuse
6. **Script Scanning (NSE)**: Cannot leverage Nmap Scripting Engine for vulnerability assessment, brute-forcing, etc.
7. **Output Formats**: Basic Python-native output only — no XML, JSON, or grepable formats
8. **Performance Optimization**: Minimal optimization — timing depends on Tor circuit latency, no timing templates available

These limitations are intentional and ensure responsible use while working within Tor's constraints.

## Installation

### Quick Setup (Recommended)

1. Clone the repository and run the setup script:

```bash
git clone https://github.com/JakkuAzzo/torNmap.git
cd torNmap
chmod +x setup.sh
./setup.sh
# or specify Python version: PYTHON=python3.10 ./setup.sh
```

2. Activate the virtual environment:

```bash
source .venv/bin/activate
```

### Manual Installation

If you prefer to install dependencies manually:

```bash
pip install -r requirements.txt
```

## Prerequisites

- **Python 3.7+**
- **Tor** running locally with SOCKS proxy enabled (default: 127.0.0.1:9050)
  - System package: `tor` 
  - Or: Tor Browser Bundle (SOCKS typically on port 9150)
- **Python packages**: `pysocks`, `stem` (installed automatically by setup.sh)

## Usage

### Basic Usage

```bash
# Scan default ports on localhost (safe default)
python torNmap.py

# Scan specific ports
python torNmap.py --target 192.168.1.1 --ports 22,80,443,8080

# Scan with verbose output
python torNmap.py --target example.com --ports 80,443 --verbose

# Scan a .onion address (requires Tor running)
python torNmap.py --url http://example.onion --ports 80,443
```

### Command-Line Options

```
usage: torNmap.py [-h] [--target TARGET | --url URL] [--ports PORTS] 
                  [--workers WORKERS] [--timeout TIMEOUT] [--rotate] 
                  [--skip-socks-check] [--verbose]

Options:
  --target, -t TARGET    Target IP or hostname (default: 127.0.0.1)
  --url, -u URL          Target URL or hostname (extracts hostname automatically)
  --ports, -p PORTS      Comma-separated port list (default: 22,80,443,8080)
  --workers, -w N        Number of concurrent workers (default: 4)
  --timeout TIMEOUT      Connection timeout in seconds (default: 10.0)
  --rotate               Rotate Tor circuit after each probe (slow, requires ControlPort)
  --skip-socks-check     Skip Tor SOCKS proxy availability check
  --verbose, -v          Show detailed configuration and scan information
```

### Examples

```bash
# Scan common web ports
python torNmap.py --target example.com --ports 80,443,8080,8443

# Scan with custom timeout and workers
python torNmap.py --target 192.168.1.1 --ports 1-1000 --timeout 5 --workers 8

# Scan .onion service (Tor must be running)
python torNmap.py --url "http://thehiddenwiki.onion" --ports 80,443

# Scan with circuit rotation (requires Tor ControlPort)
python torNmap.py --target example.com --ports 22,80,443 --rotate

# Run in CI/testing without Tor (will fail to connect but won't error on setup)
python torNmap.py --skip-socks-check --target 127.0.0.1 --ports 80
```

## Configuration

### Tor SOCKS Proxy

By default, torNmap expects Tor SOCKS5 proxy at `127.0.0.1:9050`. If using Tor Browser, change to port `9150`:

Edit `torNmap.py`:
```python
TOR_SOCKS_PORT = 9150  # Tor Browser Bundle
```

### Tor Control Port (Optional)

For circuit rotation (`--rotate`), configure Tor ControlPort:

1. Edit `/etc/tor/torrc` (or Tor Browser's torrc):
```
ControlPort 9051
CookieAuthentication 1
```

2. Restart Tor

3. Use the `--rotate` flag when scanning

## Output Format

torNmap provides simple, readable output:

```
Starting scan of example.com
Scanning 4 port(s) via Tor SOCKS 127.0.0.1:9050
------------------------------------------------------------
Port    22: closed               (took 0.52s)
Port    80: open                 (took 0.48s)
Port   443: open                 (took 0.51s)
Port  8080: filtered/timeout     (took 10.0s)
------------------------------------------------------------

Scan Summary:
  Total ports scanned: 4
  Scan duration: 11.53 seconds
  Port status breakdown:
    closed: 1
    filtered/timeout: 1
    open: 2

  Open ports: 80, 443
```

### Port Status Meanings

- **open**: TCP connection successful (port is accepting connections)
- **closed**: Connection refused (port is not listening)
- **filtered/timeout**: Connection timed out (firewall, rate limiting, or slow exit node)
- **error:XXX**: Other errors (proxy issues, network problems, etc.)

## Security and Ethical Use

⚠️ **IMPORTANT SECURITY NOTICE** ⚠️

- **Only scan systems you own or have explicit written permission to test**
- Unauthorized port scanning may be illegal in your jurisdiction
- torNmap is for educational purposes and authorized security testing only
- The tool logs are your responsibility — ensure you can justify all scans
- Tor provides anonymity but does not make unauthorized scanning legal or ethical

## Troubleshooting

### "Tor SOCKS proxy not reachable"

**Solution**: Ensure Tor is running
```bash
# On Linux
sudo systemctl start tor
# Or check if Tor Browser is running

# Verify Tor is listening
netstat -tuln | grep 9050
```

### "All ports show error:ProxyConnectionError"

**Cause**: Tor proxy not running or wrong port

**Solution**: 
1. Start Tor: `sudo systemctl start tor`
2. Check Tor port (9050 for system Tor, 9150 for Tor Browser)
3. Update `TOR_SOCKS_PORT` in script if needed

### "ControlPort not available" (when using --rotate)

**Solution**: Enable ControlPort in Tor configuration
```bash
# Edit /etc/tor/torrc
echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc
echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor
```

### Slow scanning

**Cause**: Tor circuits have variable latency

**Solution**:
- Increase timeout: `--timeout 15`
- Reduce workers: `--workers 2`
- Accept that Tor scanning is inherently slower than direct scanning

## Why Use torNmap?

### Educational Value
- Learn about TCP connections and port scanning fundamentals
- Understand Tor network architecture and SOCKS proxies
- Practice Python socket programming and concurrent execution

### Use Cases
- Testing .onion hidden services
- Privacy-focused reconnaissance (with permission)
- Learning network security basics
- Understanding scanning limitations over Tor

### What torNmap Is NOT
- **Not a replacement for Nmap**: Lacks 95% of Nmap's features
- **Not for stealth**: TCP connect scans are easily detected
- **Not for production**: Educational tool with basic functionality
- **Not for unauthorized use**: Strictly for authorized testing only

## Comparison with Nmap

| Feature | Nmap | torNmap |
|---------|------|---------|
| Scan Types | SYN, ACK, FIN, Xmas, Null, UDP, SCTP, etc. | TCP connect only |
| Service Detection | Yes, extensive | No |
| OS Fingerprinting | Yes, advanced | No |
| Firewall Evasion | Fragmentation, decoys, spoofing | None |
| NSE Scripts | 600+ scripts | None |
| Output Formats | XML, JSON, grepable, normal | Basic text only |
| Performance | Highly optimized | Limited by Tor latency |
| Port Range | Unlimited | Max 1000 ports |
| Anonymity | No (direct connection) | Yes (via Tor) |

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style and documentation standards
- New features align with the tool's educational purpose
- Security best practices are maintained
- All contributions respect ethical use guidelines

## License

This project is provided for educational purposes. Use responsibly and ethically.

## Disclaimer

The authors and contributors are not responsible for misuse of this tool. Users are solely responsible for complying with applicable laws and regulations. Unauthorized port scanning and network reconnaissance may be illegal in your jurisdiction.

## Acknowledgments

- Built with [PySocks](https://github.com/Anorov/PySocks) for SOCKS proxy support
- Uses [Stem](https://stem.torproject.org/) for Tor control protocol
- Inspired by [Nmap](https://nmap.org/) — the definitive network scanner

---

**Remember**: With great power comes great responsibility. Use this tool wisely and ethically.
