NetTest

**NetTest** is a raw network diagnostic and censorship detection tool written in Go. It combines the functionality of **WinMTR**, **Ping**, and **OONI** into a single, dependency-free binary.

It is designed to detect packet loss, latency jitter, DNS spoofing, and Deep Packet Inspection (DPI) blocking on specific ports (web or game servers).

## Features

*   **Advanced MTR (Trace + Ping):** Real-time path analysis with per-hop packet loss and jitter calculation.
*   **Censorship Detection:**
    *   **DNS Layer:** Detects DNS spoofing by comparing local resolution vs. trusted DNS (Google/Cloudflare).
    *   **Transport Layer (TCP):** Checks connectivity to specific ports (e.g., 443, 80, 25565).
    *   **Application Layer (HTTP):** Detects DPI blocking where TCP connects but HTTP requests hang or reset.
*   **Smart Target Parsing:** Automatically distinguishes between IPs, Domains, and `Host:Port` targets.
*   **Cross-Platform:** Runs native on Windows (with auto-firewall handling) and Linux.

## Usage

**Note:** NetTest requires **Administrator** (Windows) or **Root/Sudo** (Linux) privileges because it constructs raw ICMP packets.

### 1. MTR (Traceroute + Stats)
Performs a route trace to the target, calculating packet loss and jitter for the destination.

```bash
# Run MTR to google.com
nettest --mtr google.com

# Send 10 packets per hop (more accurate jitter)
nettest --mtr --count 10 google.com
```

### 2. Censorship & Ban Check
Analyzes if a specific host or service is blocked by your ISP or government.

**Check a Website (Auto-defaults to Port 443):**
```bash
nettest --censor google.com
```
> Performs DNS check, TCP Connect check, and HTTP/DPI check.

**Check a Game Server (e.g., Minecraft):**
```bash
nettest --censor mc.hypixel.net:25565
```
> skips DPI check (non-web port), performs DNS check, tests TCP connectivity to port 25565.

**Check an IP Address:**
```bash
nettest --censor 1.1.1.1
```
> Skips DNS check, tests basic reachability.

### 3. Standard Ping
Simple ICMP echo request to measure reachability and round-trip time.

```bash
nettest --ping 8.8.8.8
```

## Command Flags

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--mtr` | `bool` | `false` | Run MTR (Traceroute + Ping stats). |
| `--censor` | `bool` | `false` | Run censorship/ban detection (DNS, TCP, DPI). |
| `--ping` | `bool` | `false` | Run standard ICMP ping test. |
| `--dns` | `string` | `8.8.8.8` | Trusted DNS server to use for spoofing checks. |
| `--count` | `int` | `0` | Number of packets to send (0 = 4 for Ping, 1 pass for MTR). |
| `-o` | `string` | `(none)` | Save the final report to a specific file path. |

Installation

No installation or dependencies are required. NetTest is a single, standalone binary.

### Windows
1.  Download `nettest-windows-amd64.exe` from the Releases page.
2.  Open **Command Prompt** or **PowerShell** as **Administrator**.
3.  Run the tool:
    ```powershell
    .\nettest-windows-amd64.exe --censor google.com
    ```

### Linux
1.  Download `nettest-linux-amd64` (or `arm64` for Raspberry Pi).
2.  Make the binary executable:
    ```bash
    chmod +x nettest-linux-amd64
    ```
3.  Run with `sudo` (required for raw socket access):
    ```bash
    sudo ./nettest-linux-amd64 --censor google.com
    ```

## Building from Source (Optional)

If you prefer to compile the code yourself, you must have Go 1.25+ installed.

```bash
git clone https://github.com/yourname/nettest
cd nettest
go build .
```

## How It Works

### The MTR Engine
Unlike standard `tracert`, NetTest measures **Jitter** (variance in latency). High jitter often indicates network congestion or poor routing, even if packet loss is 0%.

### The Censorship Engine
1.  **Resolution:** Resolves the target using the System DNS (ISP).
2.  **Verification:** Resolves the target using a Trusted DNS (e.g., 8.8.8.8). If IPs mismatch significantly, **DNS Spoofing** is detected.
3.  **Reachability:** Attempts a TCP Handshake. If this fails while Ping works, **Port Blocking** is detected.
4.  **Inspection:** If the port is 80/443, sends a valid HTTP header. If TCP works but HTTP fails/timeouts, **Deep Packet Inspection (DPI)** is detected.
