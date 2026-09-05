# PACK3T 📡

> A command-line packet capture and analysis tool powered by local LLMs.

PACK3T lets you capture live network traffic, inspect packets by protocol, store captures to PCAP files, and run AI-driven analysis and anomaly detection — all from your terminal. It uses [Ollama](https://ollama.ai/) to run LLMs locally, so no data ever leaves your machine.

---

## Features

- **Live packet capture** with interface selection, timeout, and count controls
- **Protocol filtering** for TCP, UDP, ICMP, and more
- **In-memory packet store** for fast inspection and querying
- **PCAP export** to save captures for later use
- **LLM-powered analysis** — summarize traffic patterns using a local model
- **Anomaly detection** — scan for suspicious IPs, ports, and attack indicators
- **SQLite-backed storage** via `packets.db` for persistence across sessions

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai/) installed and running locally
- `llama3.2` model pulled (or another model of your choice)
- Admin/root privileges (required for packet capture)
- Windows: PowerShell available (used to pipe prompts to Ollama)

### Python Dependencies

```
scapy>=2.7.0
requests>=2.31.0
```

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/BHawkins235/PACK3T.git
cd PACK3T
pip install -r requirements.txt
```

Make sure Ollama is running and the model is available:

```bash
ollama pull llama3.2
ollama serve
```

---

## Usage

Run PACK3T using `python PACK3T.py <command> [options]`.

### Commands

#### `capture` — Capture live packets

```bash
python PACK3T.py capture -i <interface> -t <seconds> -c <count> -p <protocol>
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--interface` | Network interface index | `0` |
| `-t`, `--timeout` | Capture duration in seconds | `10` |
| `-c`, `--count` | Max packets to store after capture | *(all)* |
| `-p`, `--protocol` | Filter by protocol (e.g. `tcp`, `udp`, `icmp`) | *(all)* |

**Example:**
```bash
python PACK3T.py capture -i 1 -t 30 -p tcp
```

---

#### `list` — List captured packets in memory

```bash
python PACK3T.py list [-p <protocol>]
```

**Example:**
```bash
python PACK3T.py list -p udp
```

---

#### `interfaces` — List available network interfaces

```bash
python PACK3T.py interfaces
```

Use this to find the correct interface index for the `capture` command.

---

#### `analyze` — Analyze packets with a local LLM

```bash
python PACK3T.py analyze [-m <model>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m`, `--model` | Ollama model to use | `llama3.2` |

Sends the captured packets to your local LLM for a plain-language summary of traffic patterns, protocols, IPs, and ports.

**Example:**
```bash
python PACK3T.py analyze -m llama3.2
```

---

#### `detect` — Detect security anomalies

```bash
python PACK3T.py detect [-m <model>]
```

Scans captured packets for suspicious behavior, including unusual ports, potential attack patterns, and data exfiltration indicators.

**Example:**
```bash
python PACK3T.py detect -m llama3.2
```

---

#### `store` — Save packets to a PCAP file

```bash
python PACK3T.py store [-f <filename>] [-d <destination>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--file` | Output PCAP file name | `packets.pcap` |
| `-d`, `--destination` | Storage destination | `local` |

**Example:**
```bash
python PACK3T.py store -f capture_2026.pcap
```

---

#### `clear` — Clear packets from memory

```bash
python PACK3T.py clear
```

---

## Project Structure

```
PACK3T/
├── PACK3T.py        # CLI entry point — handles all commands
├── packets.py       # Packet capture, filtering, and in-memory store
├── analyzer.py      # LLM integration for analysis and anomaly detection
├── storage.py       # SQLite-backed persistence (packets.db)
├── packets.db       # Local SQLite database
├── requirements.txt # Python dependencies
└── LICENSE          # MIT License
```

---

## Example Workflow

```bash
# 1. See available interfaces
python PACK3T.py interfaces

# 2. Capture 60 seconds of TCP traffic on interface 1
python PACK3T.py capture -i 1 -t 60 -p tcp

# 3. List what was captured
python PACK3T.py list

# 4. Ask the LLM to summarize the traffic
python PACK3T.py analyze

# 5. Scan for anything suspicious
python PACK3T.py detect

# 6. Save to a PCAP file
python PACK3T.py store -f my_capture.pcap

# 7. Clear memory
python PACK3T.py clear
```

---

## Things to add to this project

  - add a command to export the report into a file after running 

## Notes

- Packet capture requires elevated privileges. Run with `sudo` on Linux/macOS or as Administrator on Windows.
- The LLM integration uses Ollama's CLI via PowerShell on Windows. Ensure `ollama` is in your system PATH.
- To use a different model, pass `-m <model_name>` to `analyze` or `detect`. Any model available in your local Ollama installation will work.

---

## License

MIT © 2026 Blake — see [LICENSE](LICENSE) for details.
