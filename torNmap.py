# also run Tor locally (system package tor / torbrowser) so SOCKS at 127.0.0.1:9050
# filename: tor_tcp_probe.py
# Educational: lightweight TCP connect scanner over Tor SOCKS5
# Defaults to localhost to avoid accidental unauthorized scanning.
# Use only on systems you control or with explicit permission.

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

# CONFIG
TOR_SOCKS_HOST = '127.0.0.1'
TOR_SOCKS_PORT = 9050   # change to 9150 if using Tor Browser bundle
TOR_CONTROL_PORT = 9051 # if you configured controlport in torrc; optional
TOR_CONTROL_PASS = None # set if you configured HashedControlPassword

DEFAULT_TARGET = '127.0.0.1'   # safe default
PORTS = [22, 80, 443, 8080]    # small list for demo; enlarge responsibly
CONNECT_TIMEOUT = 10.0         # seconds

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
# Interpretation helper
def interpret(exc, elapsed):
    if exc is None:
        return "open"
    # ConnectionRefusedError => closed
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    # socket.timeout or hung => filtered/timeout (could be exit node or firewall)
    if isinstance(exc, socket.timeout):
        return "filtered/timeout"
    # generic socket error -> show as filtered/no-route
    return f"error:{type(exc).__name__}"

def probe_tcp_via_tor(target, port, socks_host=TOR_SOCKS_HOST, socks_port=TOR_SOCKS_PORT, timeout=CONNECT_TIMEOUT):
    """
    Attempt a TCP connect to (target,port) via Tor socks proxy.
    Returns tuple: (port, status, elapsed_seconds, error_or_none)
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
    status = interpret(err, elapsed)
    return port, status, round(elapsed, 2), err


def check_tor_socks(host=TOR_SOCKS_HOST, port=TOR_SOCKS_PORT, timeout=2.0):
    """Quick check whether a SOCKS listener is reachable at host:port.
    Returns True if a TCP connection to the proxy is possible, False otherwise.
    This does a plain TCP connect to the SOCKS port (doesn't speak SOCKS).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_tor_control(control_port=TOR_CONTROL_PORT, password=TOR_CONTROL_PASS, timeout=2.0):
    """Check whether Tor ControlPort is reachable and authenticates.
    Returns True if Controller.from_port + authenticate succeeds, False otherwise.
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
    """Request a new Tor circuit (NEWNYM). Requires Tor to have ControlPort enabled."""
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

def scan_ports(target=DEFAULT_TARGET, ports=PORTS, rotate_circuit=False, max_workers=4):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(probe_tcp_via_tor, target, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p, status, elapsed, err = fut.result()
            results.append((p, status, elapsed))
            print(f"Port {p:5d}: {status} (took {elapsed}s)")
            # optional: rotate Tor circuit between probes if you must (very slow)
            if rotate_circuit:
                ok = rotate_tor_circuit()
                print(f"  requested NEWNYM -> {ok}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tiny TCP probe over Tor (educational). DEFAULT target=127.0.0.1")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--target", "-t", default=DEFAULT_TARGET,
                       help="target IP or hostname (default: %(default)s)")
    group.add_argument("--url", "-u",
                       help="target URL or hostname (e.g. http://site.onion or site.onion). If given, hostname is extracted and used as the target")
    parser.add_argument("--ports", "-p", default=",".join(str(x) for x in PORTS),
                        help="comma-separated ports")
    parser.add_argument("--rotate", action="store_true", help="rotate Tor circuit after each probe (slow)")
    parser.add_argument("--skip-socks-check", action="store_true",
                        help="skip checking for a local Tor SOCKS listener (useful for CI or headless runs)")
    args = parser.parse_args()

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]

    # If URL provided, extract hostname (works for .onion addresses as well)
    if args.url:
        raw = args.url.strip()
        # If value looks like a scheme-less hostname, urlparse will put it in path — handle that.
        if "//" not in raw and ("/" in raw):
            # e.g. example.onion/some/path -> take first segment
            raw = raw.split("/")[0]
        parsed = urlparse(raw if "//" in raw else f"//{raw}", scheme="http")
        host = parsed.hostname or raw
        target = host
    else:
        target = args.target

    # Verify SOCKS proxy unless explicitly skipped
    if not args.skip_socks_check:
        ok = check_tor_socks()
        if not ok:
            print(
                f"ERROR: Tor SOCKS proxy not reachable at {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}.\n"
                "Please start Tor (system package or Tor Browser) or run with --skip-socks-check if intentional.")
            sys.exit(1)

    # If rotation requested, verify ControlPort/auth; if unavailable, warn and disable rotation
    rotate_flag = args.rotate
    if rotate_flag:
        ctrl_ok = check_tor_control()
        if not ctrl_ok:
            print(
                f"WARNING: Tor ControlPort not available or authentication failed on port {TOR_CONTROL_PORT}.\n"
                "Rotation (--rotate) will be disabled. To enable rotation, set ControlPort in torrc and configure authentication.")
            rotate_flag = False

    if args.url:
        print(f"Scanning {target} (from URL {args.url}) ports {ports} via Tor SOCKS {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    else:
        print(f"Scanning {target} ports {ports} via Tor SOCKS {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    scan_ports(target=target, ports=ports, rotate_circuit=rotate_flag)
