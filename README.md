<p align="center">
  <img src="flagr/flagr.png" alt="Flagr" width="120"/>
</p>

<h1 align="center">Flagr</h1>

<p align="center">
  <b>Automatic CTF Challenge Solver</b><br>
  Point it at a target. Let it find the flag.
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#units">Units</a> &bull;
  <a href="#docker">Docker</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

Flagr is a multithreaded Python 3 framework that automates solving common Capture the Flag challenges. Hand it a file, URL, or raw data and it will run through **96 built-in units** covering crypto, stego, forensics, web, pwn, encoding, and more — reporting flags as it finds them.

```
$ flagr --force -f "FLAG{.*?}" "RkxBR3t0aGlzX2lzX2FfYmFzZTY0X2ZsYWd9"

flagr - running - 12 units queued
Target completed in 0.34 seconds after 8 unit cases
  base64(RkxBR3t0aGlzX2lzX2FfYmFzZTY0X2ZsYWd9) ->
    Flag: FLAG{this_is_a_base64_flag} - (copied)
```

## Installation

### One-liner (Ubuntu/Debian/Fedora/Arch)

```bash
curl -fsSL https://raw.githubusercontent.com/imattas/Flagr/main/install.sh | sudo bash
```

This installs system dependencies, Python packages, and optional stego tools automatically.

### Manual

```bash
# System deps (Ubuntu/Debian)
sudo apt update && sudo apt install -y python3 python3-pip python3-dev python3-venv \
    build-essential libffi-dev libssl-dev libgmp-dev libmpfr-dev libmpc-dev \
    libmagic1 libenchant-2-dev tesseract-ocr libimage-exiftool-perl \
    binwalk foremost steghide poppler-utils tcpflow unzip git nodejs ruby

# Clone and install
git clone https://github.com/imattas/Flagr.git && cd Flagr
pip3 install .
```

### Docker

```bash
cd docker
docker build -t flagr .
docker run -v "$(pwd)/ctf:/data" -it flagr
```

See [`docker/`](docker/) for details.

## Quick Start

```bash
# Solve a base64 challenge
flagr -f "FLAG{.*?}" "RkxBR3t0aGlzX2lzX2FfYmFzZTY0X2ZsYWd9"

# Solve a file
flagr -f "picoCTF{.*?}" challenge.png

# Solve a URL
flagr -f "FLAG{.*?}" "http://ctf.example.com/challenge"

# Run a specific unit only
flagr -f "FLAG{.*?}" -u steghide challenge.jpg

# Force overwrite previous results
flagr --force -f "FLAG{.*?}" target.txt
```

## Usage

Flagr provides an interactive REPL shell by default:

```
flagr - waiting - 0 units queued
> target add ./challenge.bin
[+] ./challenge.bin: queuing target

flagr - running - 14 units queued
> status
running - 14 units queued - 42 cases evaluated

> target list
./challenge.bin - completed
 hash: 2f0a02add67b58de837c7be054ae9e77
 Flag: FLAG{solved_it}
```

### REPL Commands

| Command | Description |
|---------|-------------|
| `target add <target>` | Queue a file, URL, or raw data for solving |
| `target list` | Show all targets and their status |
| `target solution <hash>` | Show the solution chain for a target |
| `target stop <hash>` | Stop processing a target |
| `status` | Show thread activity |
| `monitor add <dir>` | Watch a directory and auto-queue new files |
| `set` | View/modify runtime configuration |
| `config <file>` | Load a `.ini` configuration file |
| `batch <targets...>` | Queue multiple targets at once |
| `notes add <key> <text>` | Add notes to a challenge |
| `export <file>` | Export solutions as markdown, JSON, or text |
| `ctf list` | List challenges from a connected CTF platform |
| `ctf queue <id>` | Queue a CTF challenge for solving |
| `quit` | Exit cleanly |

### Configuration

Create a `.ini` file for recurring settings:

```ini
[manager]
flag-format=FLAG{.*?}
auto=yes
threads=8
outdir=./results

[ctf]
provider=ctfd
url=http://ctf.example.com
username=user
password=pass
auto-submit=yes
```

```bash
flagr -c ctf.ini
```

### CLI Flags

```
flagr [-h] [-c CONFIG] [-f FLAG] [-u UNIT] [-e EXCLUDE]
      [-a] [-m MANAGER] [-t TIMEOUT] [--force] [targets ...]
```

| Flag | Description |
|------|-------------|
| `-f`, `--flag` | Flag format regex (e.g. `FLAG{*}` or `picoCTF{*}`) |
| `-c`, `--config` | Path to `.ini` config file |
| `-u`, `--unit` | Run only specific unit(s) |
| `-e`, `--exclude` | Exclude unit(s) from running |
| `-a`, `--auto` | Auto-select units for recursive targets |
| `-t`, `--timeout` | Global timeout in seconds |
| `--force` | Remove previous results before running |

## Units

Flagr ships with **96 units** across 17 categories:

| Category | Units | Examples |
|----------|-------|---------|
| **Crypto** | 24 | caesar, vigenere, xor, rsa, affine, atbash, substitution, jwt, polybius |
| **Raw/Encoding** | 12 | base64, base32, base58, base85, ascii85, morse, unhexlify, urldecode |
| **Web** | 15 | sqli, nosqli, ssti, ssrf, xxe, robots, cookies, spider, dirbuster |
| **PWN** | 7 | checksec, overflow, ret2win, ret2libc, shellcode, formatstring |
| **Stego** | 7 | steghide, stegsnow, jsteg, lsb, png_chunks, dtmf, whitespace |
| **Esoteric** | 6 | brainfuck, malbolge, ook, cow, jsfuck, pikalang |
| **Misc** | 4 | blockchain, xor_bruteforce, freq_substitution, pickle_deserialize |
| **Network** | 3 | netcat, pwntools, template_solver |
| **Forensics** | 2 | file_carve, pcap_creds |
| **PDF** | 1+ | pdfimages, pdfinfo, pdfcrack, pdf2text |
| **Other** | 15+ | apktool, binwalk, foremost, tesseract, gunzip, unzip, extract, ltrace |

Units that depend on external binaries (steghide, binwalk, foremost, etc.) will be skipped if the binary is not installed. Flagr warns you at startup about any missing dependencies.

## How It Works

```
Target (file, URL, raw data)
    |
    v
  Manager (thread pool)
    |
    +--> Unit 1 (base64 decode)  --> found data --> recurse
    +--> Unit 2 (strings)        --> found flag!
    +--> Unit 3 (binwalk)        --> extracted files --> recurse
    +--> Unit 4 (steghide)       --> extracted data --> check for flag
    ...
```

1. **Target** - Flagr wraps your input (file, URL, or raw bytes) into a Target object
2. **Matching** - The Finder scans all registered units and creates instances for each one that applies
3. **Evaluation** - Units run in parallel threads, each attempting to solve or extract data
4. **Recursion** - Any data or artifacts produced get fed back as new targets (up to a configurable depth)
5. **Flag detection** - Every piece of output is checked against your flag format regex

## CTF Platform Integration

Flagr integrates directly with CTFd-compatible platforms:

```ini
[ctf]
provider=ctfd
url=http://ctf.example.com
username=youruser
password=yourpass
auto-submit=yes
```

```
> ctf list
ID  Title           Points
1   Easy Crypto     100
2   Web Challenge   200

> ctf queue 1
[+] ctf: queuing challenge_file.txt
[+] ctf: correct flag for Easy Crypto
```

## Disclaimer

**Flagr will automatically run code and perform potentially intrusive actions against its target.** This includes SQL injection, local file inclusion testing, web shell uploads, and remote code execution attempts.

**Only run Flagr against systems you have explicit permission to test.**

We are not responsible for any damage caused by using this tool.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

## Credits

Flagr is a fork of [Katana](https://github.com/JohnHammond/katana) by John Hammond and Caleb Stewart. Original unit contributors:

- crypto.dna - voidUpdate, Zwedgy
- crypto.t9 - Zwedgy, r4j
- esoteric.ook - Liikt
- esoteric.cow - Drnkn
- stego.audio_spectrogram - Zwedgy
- stego.dtmf_decoder - Zwedgy
- stego.whitespace - l14ck3r0x01
- hash.md5 - John Kazantzis
- esoteric.jsfuck - Zwedgy
- crypto.playfair - voidUpdate
- crypto.nato_phonetic - voidUpdate

## License

GPL-3.0 - See [LICENSE.txt](LICENSE.txt)
