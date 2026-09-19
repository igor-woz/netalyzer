# netalyzer

A command-line network traffic analyzer in Python. Captures live packets or reads a `.pcap`, then reports protocol distribution, top talkers, bandwidth over time, and exports the results to JSON, CSV, or Matplotlib charts.

Built with [Scapy](https://scapy.net/) for capture and parsing, [Typer](https://typer.tiangolo.com/) for the CLI, [Rich](https://rich.readthedocs.io/) for terminal output, and [Matplotlib](https://matplotlib.org/) for charts.

This project is a reimplementation of the Python network traffic analyzer from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/network-traffic-analyzer). See [Attribution and licensing](#attribution-and-licensing).

---

## Features

- **Live capture** on any interface, with kernel-level BPF filtering and graceful `Ctrl+C` shutdown
- **Offline analysis** of `.pcap` files via a streaming reader, so large captures don't have to fit in memory
- **Protocol identification** for TCP, UDP, ICMP, ARP, DNS, HTTP, and HTTPS
- **Top talkers** — per-host packet and byte counts, sent and received
- **Conversation tracking** between host pairs
- **Bandwidth sampling** at one-second intervals during live capture
- **Export** to JSON (statistics plus per-packet records) or CSV
- **Charts** — protocol bar and pie charts, a top-hosts horizontal bar chart, and a bandwidth-over-time line chart
- **Cross-platform permission checks** that tell you exactly what's missing on Linux (root / `CAP_NET_RAW`), macOS (`/dev/bpf*`), and Windows (Npcap + Administrator)

## Architecture

Capture uses a producer–consumer split so that packet parsing never blocks the sniffer:

```
  AsyncSniffer (Scapy)          bounded Queue            processor thread
  ──────────────────── enqueue ─────────────── dequeue ──────────────────
   raw packets                  10,000 slots             extract_packet_info
                                drops counted                   │
                                when full                       v
                                                          StatsCollector
                                                        (mutex-protected)
```

| Module | Responsibility |
|--------|----------------|
| `src/main.py` | Typer CLI — `capture`, `analyze`, `stats`, `export`, `chart`, `interfaces` |
| `src/capture.py` | `CaptureEngine`, `GracefulCapture` context manager, permission checks |
| `src/analyzer.py` | Protocol identification and packet field extraction; pcap reading |
| `src/statistics.py` | Thread-safe `StatsCollector` — counters, per-host stats, bandwidth samples |
| `src/models.py` | Frozen dataclasses and the `Protocol` enum |
| `src/filters.py` | `FilterBuilder` for composing BPF expressions; BPF validation via Scapy |
| `src/export.py` | JSON and CSV serialization |
| `src/visualization.py` | Matplotlib chart generation (headless `Agg` backend) |
| `src/output.py` | Rich console tables and formatting |
| `src/constants.py` | Centralized constants — ports, byte units, chart defaults, color scheme |
| `src/exceptions.py` | Exception hierarchy rooted at `NetAlyzerError` |

## Requirements

- Python 3.11 or newer (the code uses `StrEnum` and `typing.Self`)
- `scapy`, `typer`, `rich`, `matplotlib`
- Packet capture privileges:
  - **Linux** — run as root, or grant the binary `CAP_NET_RAW`
  - **macOS** — run as root, or install Wireshark's ChmodBPF helper for access to `/dev/bpf*`
  - **Windows** — [Npcap](https://npcap.com/) installed, running as Administrator

## Installation

```bash
git clone https://github.com/igor-woz/netalyzer.git
cd netalyzer

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install scapy typer rich matplotlib
```

There is no packaged entry point yet — `pyproject.toml` is a placeholder. Run the CLI as a script:

```bash
python src/main.py --help
```

Because `sudo` resets `PATH`, invoke the virtualenv interpreter directly when capturing:

```bash
sudo .venv/bin/python src/main.py capture -i eth0 -c 100
```

## Usage

```
Usage: netalyzer [OPTIONS] COMMAND [ARGS]...

Commands:
  capture      Capture live network packets
  analyze      Analyze packets from a pcap file
  stats        Display statistics from a pcap file
  export       Export capture data to csv or json
  chart        Generate charts from capture data
  interfaces   List all available network interfaces
```

### `interfaces`

List what you can capture on:

```bash
python src/main.py interfaces
```

### `capture`

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--interface` | `-i` | Interface to capture on | all interfaces |
| `--filter` | `-f` | BPF filter expression | none |
| `--count` | `-c` | Stop after N packets | unlimited |
| `--timeout` | `-t` | Stop after N seconds | unlimited |
| `--output` | `-o` | Write results to a JSON file | none |
| `--verbose` | | Print each packet as it arrives | off |

```bash
# 100 packets on eth0
sudo .venv/bin/python src/main.py capture -i eth0 --count 100

# 30 seconds of web traffic, printed live
sudo .venv/bin/python src/main.py capture --filter "tcp port 80" --timeout 30 --verbose

# loopback capture saved to JSON
sudo .venv/bin/python src/main.py capture -i lo -c 50 -o results.json
```

The BPF expression is validated with Scapy's compiler before capture starts, so a malformed filter fails immediately instead of silently matching nothing. `Ctrl+C` stops the capture cleanly and still prints the summary.

### `analyze`

```bash
python src/main.py analyze traffic.pcap
python src/main.py analyze traffic.pcap --top-talkers 20
python src/main.py analyze traffic.pcap --json
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--top-talkers` | `-t` | How many hosts to list | `10` |
| `--json` | `-j` | Print statistics as JSON instead of tables | off |

### `stats`

```bash
python src/main.py stats traffic.pcap --bandwidth
python src/main.py stats traffic.pcap --protocol --hosts
```

| Option | Short | Description |
|--------|-------|-------------|
| `--bandwidth` | `-b` | Show bandwidth statistics |
| `--protocol` | `-p` | Show protocol distribution |
| `--hosts` | | Show the top 20 hosts |

With no flags, the protocol distribution is shown by default.

### `export`

```bash
python src/main.py export traffic.pcap -o results.json -f json
python src/main.py export traffic.pcap -o packets.csv -f csv
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Destination file (**required**) | — |
| `--format` | `-f` | `json` or `csv` | `json` |

The JSON export contains a `statistics` object (totals, capture duration, average bandwidth, protocol distribution, per-host counters, conversations, bandwidth samples) and a `packets` array of per-packet records.

### `chart`

```bash
python src/main.py chart traffic.pcap --type protocols -o protocols.png
python src/main.py chart traffic.pcap --type all -d ./charts/
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--type` | `-t` | `protocols`, `top-hosts`, `bandwidth`, or `all` | `all` |
| `--output` | `-o` | Output path for a single chart | `<type>.png` |
| `--output-dir` | `-d` | Output directory when `--type all` | current directory |

`--type all` writes `capture_protocol_pie.png`, `capture_protocol_bar.png`, `capture_top_hosts.png`, and `capture_bandwidth.png`, skipping any chart with no data behind it. Charts render through Matplotlib's headless `Agg` backend, so this works over SSH.

## Attribution and licensing

This project is a reimplementation of, and heavily inspired by, the **Python network traffic analyzer** in [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/network-traffic-analyzer) by [Carter Perez](https://github.com/CarterPerez-dev). The overall architecture — the Scapy producer–consumer capture engine, the BPF filter builder, the Rich console output, and the Matplotlib chart export — follows that project's design. The code here was written by me while working through it, with my own module layout, data models, and naming.

## Disclaimer

Packet capture may be restricted by law and by the acceptable-use policy of the network you are on. Only capture traffic on networks you own or have written permission to monitor.

