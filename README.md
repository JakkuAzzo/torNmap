# torNmap — tiny TCP probe over Tor (educational)

This small utility attempts TCP connect probes through a local Tor SOCKS5 proxy. It's intentionally lightweight and intended for learning/controlled testing only. Do not use it to scan systems you don't own or don't have permission to test.

Summary of what I changed for you
- Added `setup.sh` — creates a virtual environment (`.venv`) and installs dependencies from `requirements.txt`.
- Added `requirements.txt` — lists `pysocks` and `stem`.
- Updated `torNmap.py` so you can pass a URL/hostname with `-u/--url` (including `.onion` addresses). The script extracts the hostname from the URL and scans it the same way as passing `--target`.

Why you saw: "can't find '__main__' module in '/path/to/torNmap-1'"
- Running `python3 <directory>` asks Python to execute the directory as a package and it looks for a `__main__.py` inside that directory. The repository didn't include a `__main__.py`, so Python raised that error.
- Quick alternatives:
  - Run the script file directly:
    ```bash
    python3 torNmap-1/torNmap.py --target 127.0.0.1
    ```
  - Or change into the folder and run:
    ```bash
    cd torNmap-1
    python3 torNmap.py
    ```
  - If you prefer `python3 <directory>` semantics, I can add a `__main__.py` that will invoke `torNmap.py` for you.

Quick setup (recommended)

1) Create venv and install dependencies (script included):

```bash
cd /path/to/torNmap/torNmap-1
chmod +x setup.sh            # optional but convenient
./setup.sh
# or: PYTHON=python3.10 ./setup.sh
```

2) Activate the venv and run the tool:

```bash
source .venv/bin/activate
python torNmap.py --target 127.0.0.1
```

Using the new -u / --url option (including .onion)

- You can pass a URL or just a hostname to `-u`. The script will extract the hostname and scan the listed ports. Examples:

```bash
# scan an .onion host (works when Tor is running locally and providing SOCKS on 127.0.0.1:9050)
python torNmap.py -u 'http://exampleabcd1234.onion' -p 80,443

# scan a plain hostname
python torNmap.py -u 'example.com' -p 22,80
```

Notes about Tor and .onion addresses
- The script performs TCP connects via the local Tor SOCKS proxy (default 127.0.0.1:9050). Make sure Tor or Tor Browser is running.
- For `.onion` addresses, pass the hostname (or a URL containing it) to `-u`. Tor will route the connection correctly when you connect via the SOCKS proxy.

Options of interest
- `--ports/-p` — comma-separated port list (default: `22,80,443,8080`)
- `--rotate` — request `NEWNYM` via Tor ControlPort between probes (requires ControlPort configured and accessible)
- `--skip-socks-check` — skip pre-check that verifies a SOCKS listener exists (useful for CI or scripted runs)

Security & permissions
- This tool attempts to auto-install missing Python packages if run without a venv; prefer using the provided `setup.sh` and a virtual environment.
- Only scan systems you control or have explicit permission to test.

Want changes?
- I can add a `__main__.py` so `python3 torNmap-1` runs directly.
- I can pin dependency versions in `requirements.txt` for reproducible installs.
- I can initialize a git repo and make an initial commit if you want to start tracking changes.

Enjoy — and be responsible when scanning.
