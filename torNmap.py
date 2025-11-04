#!/usr/bin/env python3
"""
torNmap - TCP Connect Scanner over Tor

Educational tool for lightweight TCP port scanning via Tor SOCKS5 proxy.
Defaults to localhost to avoid accidental unauthorized scanning.
Use only on systems you control or with explicit permission.

LIMITATIONS (by design, due to Tor constraints):
1. Host Discovery: No ICMP, UDP, or SCTP probes - only TCP connect attempts
2. Scan Techniques: Limited to basic TCP connect probes - no SYN, ACK, FIN, 
   Xmas, Null, idle scans, or advanced scanning methods
3. Service Detection: No service/version detection or OS fingerprinting
4. Firewall Evasion: No fragmentation, spoofing, decoys, or similar evasion
5. Port Scanning: Limited port ranges to prevent abuse
6. Script Scanning: No NSE (Nmap Scripting Engine) support
7. Output Formats: Basic Python-native output only, no advanced formatting
8. Performance: Minimal optimization - timing depends on Tor circuit latency
"""

import socket
import socks          # PySocks
import time
import concurrent.futures
from stem import Signal
from stem.control import Controller
import argparse
import subprocess
import sys
from urllib.parse import urlparse

# CONFIG - Tor SOCKS and Control Port Settings
TOR_SOCKS_HOST = '127.0.0.1'
TOR_SOCKS_PORT = 9050   # change to 9150 if using Tor Browser bundle
TOR_CONTROL_PORT = 9051 # if you configured controlport in torrc; optional
TOR_CONTROL_PASS = None # set if you configured HashedControlPassword

# Scanning Configuration
DEFAULT_TARGET = '127.0.0.1'   # safe default - localhost only
DEFAULT_PORTS = [22, 80, 443, 8080]    # common service ports
CONNECT_TIMEOUT = 10.0         # seconds - higher due to Tor latency
MAX_PORTS_LIMIT = 1000         # limit to prevent abuse/extensive scanning
MAX_WORKERS_DEFAULT = 4        # conservative parallelism for Tor

import importlib.util

_missing = []
if importlib.util.find_spec("socks") is None:
    _missing.append("pysocks")
if importlib.util.find_spec("stem") is None:
    _missing.append("stem")

if _missing:
    try:
        print("Installing missing packages:", ", ".join(_missing))
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + _missing)
    except Exception as e:
        print("Package install failed:", e)
def interpret_result(exc, elapsed):
    """
    Interpret connection attempt result.
    
    Returns a human-readable status string based on the exception type.
    This provides basic status info without service/version detection.
    
    Args:
        exc: Exception raised during connection attempt, or None if successful
        elapsed: Time elapsed during connection attempt
        
    Returns:
        str: Status string ('open', 'closed', 'filtered/timeout', or error type)
    """
    if exc is None:
        return "open"
    # ConnectionRefusedError => port is closed (RST packet received)
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    # socket.timeout => filtered/timeout (could be exit node or firewall)
    if isinstance(exc, socket.timeout):
        return "filtered/timeout"
    # Generic socket error - show as filtered/no-route
    return f"error:{type(exc).__name__}"

def probe_tcp_via_tor(target, port, socks_host=TOR_SOCKS_HOST, socks_port=TOR_SOCKS_PORT, timeout=CONNECT_TIMEOUT):
    """
    Attempt a TCP connect to (target, port) via Tor SOCKS proxy.
    
    This performs a basic TCP connect scan - the simplest form of port scanning.
    Due to Tor constraints, advanced techniques like SYN scanning are not possible.
    
    Args:
        target: Target IP address or hostname
        port: Target port number
        socks_host: Tor SOCKS proxy host
        socks_port: Tor SOCKS proxy port
        timeout: Connection timeout in seconds
        
    Returns:
        tuple: (port, status, elapsed_seconds, error_or_none)
    """
    s = socks.socksocket()                    # create a socket bound to SOCKS proxy
    s.set_proxy(socks.SOCKS5, socks_host, socks_port)
    s.settimeout(timeout)
    start = time.time()
    err = None
    try:
        s.connect((target, port))
    except Exception as e:
        err = e
    finally:
        try:
            s.close()
        except:
            pass
    elapsed = time.time() - start
    status = interpret_result(err, elapsed)
    return port, status, round(elapsed, 2), err


def check_tor_socks(host=TOR_SOCKS_HOST, port=TOR_SOCKS_PORT, timeout=2.0):
    """
    Quick check whether a SOCKS listener is reachable at host:port.
    
    This does a plain TCP connect to the SOCKS port (doesn't speak SOCKS protocol).
    
    Args:
        host: SOCKS proxy host
        port: SOCKS proxy port
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_tor_control(control_port=TOR_CONTROL_PORT, password=TOR_CONTROL_PASS, timeout=2.0):
    """
    Check whether Tor ControlPort is reachable and authenticates.
    
    Args:
        control_port: Tor control port number
        password: Control port password (if configured)
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if Controller connects and authenticates, False otherwise
    """
    try:
        # Controller.from_port will raise if unreachable; use short timeout
        with Controller.from_port(port=control_port, timeout=timeout) as ctrl:
            try:
                if password:
                    ctrl.authenticate(password)
                else:
                    ctrl.authenticate()
                return True
            except Exception:
                return False
    except Exception:
        return False

def rotate_tor_circuit(control_port=TOR_CONTROL_PORT, password=TOR_CONTROL_PASS):
    """
    Request a new Tor circuit (NEWNYM signal).
    
    Requires Tor to have ControlPort enabled and proper authentication.
    This can help with anonymity but significantly slows down scanning.
    
    Args:
        control_port: Tor control port number
        password: Control port password (if configured)
        
    Returns:
        bool: True if circuit rotation successful, False otherwise
    """
    try:
        with Controller.from_port(port=control_port) as ctrl:
            if password:
                ctrl.authenticate(password)
            else:
                ctrl.authenticate()  # will attempt cookie auth
            ctrl.signal(Signal.NEWNYM)
            # give Tor a moment to create the new circuit
            time.sleep(2)
            return True
    except Exception as e:
        # control port not available or auth failed
        return False

def scan_ports(target=DEFAULT_TARGET, ports=None, rotate_circuit=False, max_workers=MAX_WORKERS_DEFAULT, timeout=CONNECT_TIMEOUT):
    """
    Scan multiple ports on a target via Tor.
    
    Performs basic TCP connect probes. Does NOT support:
    - Service/version detection
    - OS fingerprinting  
    - Advanced scan types (SYN, ACK, FIN, etc.)
    - Firewall evasion techniques
    
    Args:
        target: Target IP or hostname
        ports: List of ports to scan
        rotate_circuit: Whether to rotate Tor circuit between probes (slow)
        max_workers: Maximum number of concurrent workers (limited for Tor)
        timeout: Connection timeout in seconds
        
    Returns:
        list: List of tuples (port, status, elapsed_time)
    """
    if ports is None:
        ports = DEFAULT_PORTS
        
    # Validate port count to prevent extensive scanning
    if len(ports) > MAX_PORTS_LIMIT:
        raise ValueError(f"Port count ({len(ports)}) exceeds maximum limit ({MAX_PORTS_LIMIT})")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(probe_tcp_via_tor, target, p, timeout=timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p, status, elapsed, err = fut.result()
            results.append((p, status, elapsed))
            # Basic output format - no advanced formatting options
            print(f"Port {p:5d}: {status:20s} (took {elapsed}s)")
            # optional: rotate Tor circuit between probes if you must (very slow)
            if rotate_circuit:
                ok = rotate_tor_circuit()
                print(f"  requested NEWNYM -> {ok}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="torNmap - TCP connect scanner over Tor (educational). DEFAULT target=127.0.0.1",
        epilog="""
LIMITATIONS (by design):
  • Host Discovery: TCP connect only (no ICMP/UDP/SCTP)
  • Scan Types: Basic TCP connect (no SYN/ACK/FIN/Xmas/Null/idle scans)
  • Detection: No service/version or OS fingerprinting
  • Evasion: No fragmentation, spoofing, or decoy features
  • Port Range: Limited to prevent abuse (max 1000 ports)
  • Scripts: No NSE (Nmap Scripting Engine) support
  • Output: Basic format only (no XML/JSON/grepable output)
  • Performance: Minimal optimization (depends on Tor latency)

SECURITY: Only scan systems you own or have explicit permission to test.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--target", "-t", default=DEFAULT_TARGET,
                       help="target IP or hostname (default: %(default)s)")
    group.add_argument("--url", "-u",
                       help="target URL or hostname (e.g. http://site.onion or site.onion). "
                            "If given, hostname is extracted and used as the target")
    
    parser.add_argument("--ports", "-p", 
                        default=",".join(str(x) for x in DEFAULT_PORTS),
                        help="comma-separated ports (default: %(default)s, max: " + 
                             str(MAX_PORTS_LIMIT) + " ports)")
    
    parser.add_argument("--workers", "-w", type=int, default=MAX_WORKERS_DEFAULT,
                        help=f"number of concurrent workers (default: {MAX_WORKERS_DEFAULT})")
    
    parser.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT,
                        help=f"connection timeout in seconds (default: {CONNECT_TIMEOUT})")
    
    parser.add_argument("--rotate", action="store_true", 
                        help="rotate Tor circuit after each probe (very slow, increases anonymity)")
    
    parser.add_argument("--skip-socks-check", action="store_true",
                        help="skip checking for a local Tor SOCKS listener (useful for CI or headless runs)")
    
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="verbose output (show configuration and scan details)")
    
    args = parser.parse_args()

    # Parse and validate ports
    try:
        ports = [int(x) for x in (s.strip() for s in args.ports.split(",")) if x]
        if not ports:
            parser.error("No valid ports specified")
        if len(ports) > MAX_PORTS_LIMIT:
            parser.error(f"Port count ({len(ports)}) exceeds maximum limit ({MAX_PORTS_LIMIT})")
        # Validate port range
        for p in ports:
            if not (1 <= p <= 65535):
                parser.error(f"Port {p} is out of valid range (1-65535)")
    except ValueError as e:
        parser.error(f"Invalid port specification: {e}")

    # If URL provided, extract hostname (works for .onion addresses as well)
    if args.url:
        raw = args.url.strip()
        # If value looks like a scheme-less hostname, urlparse will put it in path — handle that.
        if "//" not in raw and "/" in raw:
            # e.g. example.onion/some/path -> take first segment
            raw = raw.split("/")[0]
        parsed = urlparse(raw if "//" in raw else f"//{raw}", scheme="http")
        host = parsed.hostname or raw
        target = host
    else:
        target = args.target

    # Display configuration if verbose
    if args.verbose:
        print("=" * 60)
        print("torNmap - TCP Connect Scanner over Tor")
        print("=" * 60)
        print(f"Target: {target}")
        if args.url:
            print(f"  (extracted from URL: {args.url})")
        print(f"Ports: {len(ports)} port(s) - {ports[:10]}{'...' if len(ports) > 10 else ''}")
        print(f"Tor SOCKS Proxy: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
        print(f"Workers: {args.workers}")
        print(f"Timeout: {args.timeout}s")
        print(f"Circuit Rotation: {'Enabled' if args.rotate else 'Disabled'}")
        print("=" * 60)
        print()
    
    # Verify SOCKS proxy unless explicitly skipped
    if not args.skip_socks_check:
        if args.verbose:
            print("Checking Tor SOCKS proxy availability...")
        ok = check_tor_socks()
        if not ok:
            print(
                f"ERROR: Tor SOCKS proxy not reachable at {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}.\n"
                "Please start Tor (system package or Tor Browser) or run with --skip-socks-check if intentional.")
            sys.exit(1)
        if args.verbose:
            print("✓ Tor SOCKS proxy is reachable\n")

    # If rotation requested, verify ControlPort/auth; if unavailable, warn and disable rotation
    rotate_flag = args.rotate
    if rotate_flag:
        if args.verbose:
            print("Checking Tor ControlPort for circuit rotation...")
        ctrl_ok = check_tor_control()
        if not ctrl_ok:
            print(
                f"WARNING: Tor ControlPort not available or authentication failed on port {TOR_CONTROL_PORT}.\n"
                "Rotation (--rotate) will be disabled. To enable rotation, set ControlPort in torrc and configure authentication.")
            rotate_flag = False
        elif args.verbose:
            print("✓ Tor ControlPort is accessible\n")

    # Display scan start message
    if args.url:
        print(f"Starting scan of {target} (from URL {args.url})")
    else:
        print(f"Starting scan of {target}")
    print(f"Scanning {len(ports)} port(s) via Tor SOCKS {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("-" * 60)
    
    # Perform the scan
    start_time = time.time()
    results = scan_ports(target=target, ports=ports, rotate_circuit=rotate_flag, 
                        max_workers=args.workers, timeout=args.timeout)
    scan_duration = time.time() - start_time
    
    # Display summary
    print("-" * 60)
    print(f"\nScan Summary:")
    print(f"  Total ports scanned: {len(results)}")
    print(f"  Scan duration: {scan_duration:.2f} seconds")
    
    # Count by status
    status_counts = {}
    for _, status, _ in results:
        status_counts[status] = status_counts.get(status, 0) + 1
    
    print(f"  Port status breakdown:")
    for status, count in sorted(status_counts.items()):
        print(f"    {status}: {count}")
    
    # List open ports
    open_ports = [p for p, s, _ in results if s == "open"]
    if open_ports:
        print(f"\n  Open ports: {', '.join(map(str, sorted(open_ports)))}")
    else:
        print(f"\n  No open ports found")
    
    if args.verbose:
        print("\nNOTE: This scan used basic TCP connect probes only.")
        print("      No service detection, OS fingerprinting, or advanced")
        print("      scan techniques were employed due to Tor constraints.")

