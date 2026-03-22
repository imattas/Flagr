---
title: Flagr
description: An automation framework for solving CTF challenges automatically.
---

Reference pages are ideal for outlining how things work in terse and clear terms.
Less concerned with telling a story or addressing a specific use case, they should give a comprehensive outline of what you're documenting.

## How to install

```bash
curl -fsSL https://raw.githubusercontent.com/imattas/Flagr/main/install.sh | sudo bash
```

This installs system dependencies (python3, binwalk, steghide, foremost, tesseract, exiftool, etc.), Python packages, optional stego tools (zsteg, jsteg, stegsnow), clones the repo to `/opt/flagr`, installs the package via pip, and puts `flagr` on your PATH.

Supports apt (Debian/Ubuntu/Kali), dnf (Fedora), pacman (Arch), and yum (RHEL/CentOS).

### Docker

```bash
cd docker
docker build -t flagr .
docker run -v "$(pwd)/ctf:/data" -it flagr
```

## How to launch

```bash
flagr                                         # interactive REPL shell
flagr -f "FLAG{.*?}" target.txt               # solve a file
flagr -f "picoCTF{.*?}" challenge.png          # solve an image
flagr -f "FLAG{.*?}" "http://ctf.com/chall"   # solve a URL
flagr -f "FLAG{.*?}" "RkxBR3tiYXNlNjR9"       # solve raw data
flagr -u steghide challenge.jpg               # run only one unit
flagr --force -f "FLAG{.*?}" target.bin        # force re-run
flagr --remote host.ctf.com 1337 ./binary      # exploit remote target
```

Without arguments, Flagr drops into an interactive REPL. With arguments, it queues targets immediately and enters the REPL for monitoring.

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `-f`, `--flag <regex>` | Flag format regex. Use `FLAG{.*?}` or `picoCTF{.*?}`. Shorthand `FLAG{*}` is expanded automatically. |
| `-c`, `--config <file>` | Path to `.ini` configuration file |
| `-u`, `--unit <name>` | Run only specific unit(s). Can be repeated: `-u steghide -u binwalk` |
| `-e`, `--exclude <name>` | Exclude unit(s). Can be repeated: `-e brainfuck -e cow` |
| `-a`, `--auto` | Auto-select units for recursive targets |
| `-t`, `--timeout <secs>` | Global timeout for all unit evaluations |
| `--force` | Remove previous results directory before running |
| `--remote <host> <port>` | Remote target for exploit delivery (pwn units) |
| `-i`, `--imagegui` | Display images as Flagr finds them |
| `-m`, `--manager <opts>` | Comma-separated manager options (e.g. `flag-format=FLAG{*},threads=8`) |
| `--<unit-name> <opts>` | Unit-specific configuration (e.g. `--steghide passphrase=secret`) |

---

## REPL Commands

The interactive shell is the primary interface. It runs a `cmd2`-based REPL with tab completion, history, and scripting support.

### target

Manage solve targets.

```
> target add ./challenge.bin           # queue a file
> target add http://ctf.com/download   # queue a URL
> target add "RkxBR3tiYXNlNjR9"        # queue raw data
> target add 10.0.0.1:1337             # queue a network target
> target list                          # show all targets + status
> target solution <hash>               # show the solution chain for a target
> target stop <hash>                   # stop processing a target
```

When a target completes, Flagr shows the solution chain — every unit that ran, what data it produced, and which one found the flag.

### batch

Queue multiple targets at once.

```
> batch file1.txt file2.png http://ctf.com/chall3
```

### monitor

Watch a directory and auto-queue new files as they appear.

```
> monitor add ./downloads              # watch a directory
> monitor list                         # show active monitors
> monitor remove ./downloads           # stop watching
```

Uses filesystem events (inotify/FSEvents) — no polling.

### status

Show current thread activity, queue depth, and evaluation progress.

```
> status
running - 14 units queued - 42 cases evaluated - 3 threads active
```

### set

View or modify runtime configuration.

```
> set                                  # show all settings
> set flag-format FLAG{.*?}            # change flag format
> set threads 8                        # change thread count
> set auto yes                         # enable auto mode
> set recurse yes                      # enable recursion
> set timeout 30                       # evaluation timeout
```

### config

Load a `.ini` configuration file at runtime.

```
> config ctf.ini
```

### notes

Attach notes to challenges for tracking.

```
> notes add chall1 "Tried caesar, didn't work"
> notes list
> notes show chall1
```

### export

Export all solutions.

```
> export results.md                    # markdown format
> export results.json                  # JSON format
> export results.txt                   # plain text
```

### CTF Platform Integration

Connect to a CTFd instance and queue challenges directly.

```
> ctf list                             # list challenges
> ctf queue 1                          # queue challenge #1
> ctf submit 1 "FLAG{answer}"          # submit a flag
> ctf scoreboard                       # show scoreboard
```

Configure in `.ini`:

```ini
[ctf]
provider=ctfd
url=http://ctf.example.com
username=youruser
password=yourpass
auto-submit=yes
```

API token authentication: set `password=token:<your-api-token>`.

### quit

Exit cleanly, stopping all threads.

```
> quit
```

---

## Units

Flagr ships with **96 units** across 17 categories. Units are Python classes that inherit from `flagr.unit.Unit`. Each unit implements:

- `validate()` — decide if the unit applies to a given target (file type, content, etc.)
- `evaluate()` — perform the actual solving, yielding results

Units run in parallel threads. Results are checked against the flag regex and optionally fed back as new targets for recursive solving.

### Crypto (24 units)

| Unit | Description |
|------|-------------|
| `caesar` | Caesar cipher (all 26 shifts) |
| `caesar255` | Extended Caesar (all 256 byte shifts) |
| `keyed_caesar` | Keyed Caesar cipher |
| `vigenere` | Vigenere cipher (with key cracking) |
| `vigenere_auto` | Auto-key Vigenere |
| `xor` | XOR with common keys |
| `affine` | Affine cipher |
| `atbash` | Atbash cipher |
| `bacon` | Bacon's cipher |
| `hill` | Hill cipher |
| `polybius` | Polybius square |
| `railfence` | Rail fence cipher |
| `rot47` | ROT47 |
| `reverse` | Reversed string |
| `substitution` | Frequency-analysis substitution |
| `quipqiup` | Online substitution cipher solver |
| `rsa` | RSA with small keys |
| `rsa_attack` | RSA common attacks (Fermat, Pollard, etc.) |
| `rsa_wiener` | RSA Wiener's attack |
| `rsa_common_modulus` | RSA common modulus attack |
| `jwt` | JWT decode and verify |
| `hashes` | Hash lookup (MD5, SHA1, etc.) |
| `phonetic` | NATO phonetic alphabet |
| `dna` | DNA codon encoding |
| `t9` | T9 phone keypad encoding |

### Raw/Encoding (12 units)

| Unit | Description |
|------|-------------|
| `base64` | Base64 decode |
| `base32` | Base32 decode |
| `base58` | Base58 decode |
| `base85` | Base85 decode |
| `ascii85` | ASCII85 decode |
| `unhexlify` | Hex string decode |
| `unbinary` | Binary string decode |
| `undecimal` | Decimal string decode |
| `morsecode` | Morse code decode |
| `urldecode` | URL percent-encoding decode |
| `unicode_decode` | Unicode escape decode |
| `qrcode` | QR code decode |

### Web (15 units)

| Unit | Description |
|------|-------------|
| `basic_sqli` | SQL injection (`' OR 1=1 #`) |
| `basic_nosqli` | NoSQL injection |
| `ssti` | Server-Side Template Injection |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `robots` | robots.txt / sitemap parsing |
| `cookies` | Cookie analysis and manipulation |
| `logon_cookies` | Cookie-based auth bypass |
| `source_leak` | Source code leak detection (.git, .svn, backup files) |
| `spider` | Web crawler for hidden pages |
| `dirbuster` | Directory brute-forcing |
| `form_submit` | Automated form submission |
| `jwt_forge` | JWT token forging (none alg, weak secret) |
| `deserialize` | Insecure deserialization |
| `git` | Git repository extraction |
| `basic_img_shell` | Image upload web shell |

### PWN (7 units)

| Unit | Description |
|------|-------------|
| `checksec` | Binary security check (NX, PIE, RELRO, canary) |
| `overflow` | Stack buffer overflow detection |
| `ret2win` | Automatic ret2win exploitation |
| `ret2libc` | Return-to-libc chain building |
| `shellcode` | Shellcode injection |
| `formatstring` | Format string vulnerability exploitation |
| `remote_exploit` | Remote binary exploitation via pwntools |

PWN units use pwntools under the hood. The `--remote <host> <port>` flag enables sending exploits to remote targets.

### Stego (11 units)

| Unit | Description |
|------|-------------|
| `steghide` | Steghide extraction (with passphrase brute-forcing) |
| `stegsnow` | Snow whitespace steganography |
| `stegsolve` | Bit-plane analysis |
| `jsteg` | JPEG steganography (jsteg) |
| `lsb` | Least Significant Bit extraction |
| `png_chunks` | PNG chunk analysis (tEXt, zTXt, iTXt) |
| `zsteg` | PNG/BMP steganography (zsteg) |
| `whitespace` | Whitespace encoding |
| `snow` | SNOW steganography |
| `audio_spectrogram` | Audio spectrogram analysis |
| `dtmf_decode` | DTMF tone decoding |

### Esoteric (6 units)

| Unit | Description |
|------|-------------|
| `brainfuck` | Brainfuck interpreter |
| `malbolge` | Malbolge interpreter |
| `ook` | Ook! interpreter |
| `cow` | COW interpreter |
| `jsfuck` | JSFuck decoder (via Node.js) |
| `pikalang` | Pikalang interpreter |

### Forensics (4 units)

| Unit | Description |
|------|-------------|
| `binwalk` | Binwalk file extraction |
| `file_carve` | Generic file carving |
| `foremost` | Foremost file recovery |
| `pcap_creds` | PCAP credential extraction |

### Misc (4 units)

| Unit | Description |
|------|-------------|
| `blockchain` | Blockchain transaction analysis |
| `xor_bruteforce` | XOR brute-force (single-byte keys) |
| `substitution` | Frequency-based substitution solver |
| `pickle_deserialize` | Python pickle deserialization |

### Other

| Unit | Description |
|------|-------------|
| `strings` | Extract printable strings |
| `grep` | Regex search through data |
| `exiftool` | EXIF metadata extraction |
| `gunzip` | Gzip decompression |
| `unzip` | Zip extraction |
| `extract` (tar) | Tar extraction |
| `pdf2text` | PDF text extraction |
| `pdfinfo` | PDF metadata |
| `pdfimages` | PDF embedded image extraction |
| `pdfcrack` | PDF password cracking |
| `apktool` | APK decompilation |
| `tesseract` | OCR text extraction |
| `tcpflow` | TCP stream reassembly |
| `ltrace` | Library call tracing |
| `netcat` | Banner grabbing / basic interaction |
| `pwntools_nc` | pwntools-based network interaction |
| `template_solver` | Templated challenge solver (math, trivia) |
| `md5` (crack) | MD5 hash cracking |

---

## How It Works

```
Target (file, URL, raw data, host:port)
    │
    ▼
  Manager (thread pool, configurable thread count)
    │
    ├──▶ Unit 1 (base64 decode)      → found data    → recurse as new target
    ├──▶ Unit 2 (strings + grep)     → found flag!   → report + stop
    ├──▶ Unit 3 (binwalk)            → extracted files → recurse each file
    ├──▶ Unit 4 (steghide)           → extracted data  → check for flag
    ├──▶ Unit 5 (caesar, 26 shifts)  → plaintext      → check for flag
    └──▶ ...96 units total
```

1. **Target wrapping** — Input (file path, URL, raw bytes, or `host:port`) is wrapped into a `Target` object that provides uniform access to raw data, file path, and metadata.

2. **Unit matching** — The `Finder` scans all registered units and calls each unit's constructor. Units that raise `NotApplicable` are skipped. Applicable units are queued with their priority.

3. **Threaded evaluation** — A configurable thread pool (default 4 threads) pulls work items from a priority queue. Each unit's `evaluate()` method runs in a thread and yields results.

4. **Flag checking** — Every piece of output from every unit is checked against the flag format regex. If it matches, the flag is reported and the target is marked solved.

5. **Recursion** — Data or files produced by units are fed back as new targets (up to a configurable depth). This handles layered challenges (e.g., base64-encoded zip containing a steganographic image).

6. **Solution chain** — Flagr tracks the parent-child relationship between units, so you can see exactly which sequence of operations solved the challenge.

### Priority System

Units have a `PRIORITY` value from 0 (highest) to 100 (lowest). Default is 50. Fast, high-success-rate units (base64, strings) run first. Slow or low-probability units (brute-force, web attacks) run later. Child units inherit scaled priority from their parent to ensure recursive results are processed promptly.

### Unit Properties

| Property | Description |
|----------|-------------|
| `PRIORITY` | 0-100, lower = runs first |
| `GROUPS` | Tags for filtering (e.g. `["crypto", "caesar"]`) |
| `BLOCKED_GROUPS` | Groups this unit won't recurse into |
| `DEPENDENCIES` | Required system binaries (e.g. `["steghide"]`) |
| `RECURSE_SELF` | Whether the unit can recurse into itself |
| `NO_RECURSE` | Disable all recursion from this unit |
| `STRICT_FLAGS` | Flag must match the entire output, not a substring |

---

## Configuration File

Create a `.ini` file for persistent settings:

```ini
[manager]
flag-format = FLAG{.*?}
auto = yes
threads = 8
outdir = ./results
recurse = yes
timeout = 30
force = no
min-data = 5

[ctf]
provider = ctfd
url = http://ctf.example.com
username = player1
password = supersecret
auto-submit = yes

[steghide]
passphrase = password123

[DEFAULT]
remote = host.ctf.com:1337
```

Load with `flagr -c ctf.ini` or `config ctf.ini` in the REPL.

### Manager Settings

| Key | Default | Description |
|-----|---------|-------------|
| `flag-format` | (none) | Regex for flag detection |
| `threads` | `4` | Worker thread count |
| `outdir` | `./results` | Output directory for artifacts |
| `auto` | `no` | Auto-select units for recursive targets |
| `recurse` | `yes` | Enable recursive target processing |
| `force` | `no` | Remove previous results before running |
| `timeout` | `0.1` | Per-unit evaluation timeout (seconds) |
| `min-data` | `5` | Minimum data length to process |
| `units` | (all) | Comma-separated list of units to run |
| `exclude` | (none) | Comma-separated list of units to skip |
| `download` | `yes` | Auto-download URL targets |
| `imagegui` | `no` | Display images in GUI |

---

## Remote Exploitation

For pwn challenges hosted on a remote server:

```bash
# From the command line
flagr --remote host.ctf.com 1337 ./challenge_binary

# Or in the REPL
> set remote host.ctf.com:1337
> target add ./challenge_binary
```

The `--remote` flag:
1. Stores the remote address in the config so all pwn units can access it
2. Enables auto mode
3. Queues both the binary (for local analysis) and the remote address (for network units)

PWN units (`ret2win`, `ret2libc`, `overflow`, `formatstring`, `shellcode`, `remote_exploit`) will:
- Analyze the local binary for vulnerabilities
- Build the exploit payload
- Deliver it to the remote target
- Capture and check the response for flags

---

## Writing Custom Units

Create a Python file in `flagr/units/<category>/`:

```python
from typing import Generator, Any
from flagr.unit import Unit as BaseUnit, NotApplicable

class Unit(BaseUnit):
    GROUPS = ["misc", "my_unit"]
    PRIORITY = 50
    DEPENDENCIES = []        # e.g. ["my_tool"]
    RECURSE_SELF = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Raise NotApplicable if this unit shouldn't run on this target
        if not self.target.is_printable:
            raise NotApplicable("not printable data")

    def evaluate(self, case: Any) -> Generator[Any, None, None]:
        """
        Perform the actual work. Yield results (strings, bytes, file paths).
        Each yielded result is checked for flags and optionally recursed.
        """
        data = self.target.raw
        result = self._do_something(data)

        if result:
            yield result

    def _do_something(self, data):
        # Your solving logic here
        return data.decode("rot13")  # example
```

The unit is auto-discovered on next run. No registration needed.

### Unit Base Classes

| Class | Use For |
|-------|---------|
| `Unit` | Generic unit |
| `FileUnit` | Units that only work on files |
| `PrintableDataUnit` | Units that expect printable input |
| `NotEnglishAndPrintableUnit` | Printable but not already English (for ciphers) |
| `NotEnglishUnit` | Not English text |
| `PwnUnit` | Binary exploitation (auto-checks for ELF) |
| `WebUnit` | Web challenges (auto-checks for URL targets) |
| `CryptoUnit` | Crypto challenges |

---

## Architecture

```
/opt/flagr/                        ← install directory
├── install.sh                     ← curl installer
├── setup.py                       ← pip package
├── requirements.txt               ← Python dependencies
├── flagr/
│   ├── __init__.py                ← exports Manager, Target, Unit, Finder
│   ├── __main__.py                ← CLI entry point + arg parsing
│   ├── manager.py                 ← thread pool, work queue, recursion
│   ├── monitor.py                 ← result reporting (logging, JSON)
│   ├── target.py                  ← target abstraction (file, URL, raw, network)
│   ├── unit.py                    ← base Unit class + Finder (auto-discovery)
│   ├── util.py                    ← shared utilities
│   ├── repl/
│   │   ├── __init__.py            ← cmd2-based interactive shell
│   │   ├── ctf.py                 ← CTF platform base class
│   │   ├── ctfd.py                ← CTFd provider
│   │   └── pico.py                ← picoCTF provider
│   └── units/                     ← 96 solving units
│       ├── raw/                   ← encoding (base64, hex, morse, etc.)
│       ├── crypto/                ← ciphers (caesar, vigenere, rsa, etc.)
│       ├── web/                   ← web attacks (sqli, ssti, ssrf, etc.)
│       ├── pwn/                   ← binary exploitation
│       ├── stego/                 ← steganography
│       ├── esoteric/              ← esoteric languages
│       ├── forensics/             ← file carving, pcap
│       ├── misc/                  ← blockchain, xor brute, pickle
│       ├── network/               ← netcat, pwntools
│       ├── ocr/                   ← tesseract
│       ├── pcap/                  ← tcpflow
│       ├── pdf/                   ← pdf tools
│       ├── rev/                   ← reverse engineering
│       ├── apk/                   ← Android APK
│       ├── gzip/                  ← decompression
│       ├── tar/                   ← extraction
│       └── zip/                   ← extraction
├── tests/                         ← unit tests
├── examples/                      ← usage examples
│   ├── quick.py                   ← programmatic usage
│   └── everything.py              ← full example
└── docker/                        ← Docker support
```

---

## Programmatic Usage

Flagr can be used as a Python library:

```python
from flagr.manager import Manager
from flagr.monitor import LoggingMonitor

monitor = LoggingMonitor()
manager = Manager(monitor=monitor)

manager["manager"]["flag-format"] = "FLAG{.*?}"
manager.start()
manager.queue_target("./challenge.bin")

if manager.join(timeout=30):
    for flag in monitor.flags:
        print(f"Found: {flag}")
```

---

## Disclaimer

Flagr automatically runs code and performs potentially intrusive actions against targets. This includes SQL injection, local file inclusion, web shell uploads, and remote code execution attempts.

**Only run Flagr against systems you have explicit permission to test.**
