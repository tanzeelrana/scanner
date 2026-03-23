# Network Recon & Vulnerability Scanner

Combines **Shodan**, **Censys**, **NVD**, **Vulners**, and **Nmap** to give a comprehensive picture of open ports, running services, and known CVEs for a given IP address.

> **For authorized security research only.** Only scan systems you own or have explicit permission to test.

---

## Requirements

- Python 3.7+
- `nmap` installed and in your PATH
- Python dependencies:

```bash
pip install -r requirements.txt
```

### Installing nmap

**macOS**

Homebrew's nmap bottle currently has a broken `openssl@1.1` dependency. Use the official installer instead:

1. Download the `.dmg` from [nmap.org/download](https://nmap.org/download#macosx)
2. Open the `.dmg` and run the installer package
3. Verify: `nmap --version`

Alternatively, build from source via Homebrew (takes a few minutes):

```bash
brew install --build-from-source nmap
```

**Linux (Debian/Ubuntu)**

```bash
sudo apt install nmap
```

**Linux (RHEL/Fedora)**

```bash
sudo dnf install nmap
```

---

## Setup

1. Copy `.env` and fill in your API keys:

```bash
cp .env .env  # already provided — just open it and add your keys
```

2. Edit `.env` with your actual keys:

```env
SHODAN_API_KEY="..."    # https://shodan.io
NVD_API_KEY="..."       # https://nvd.nist.gov/developers/request-an-api-key
CENSYS_API_KEY="..."    # https://censys.io → Account → API
VULNERS_API_KEY="..."   # https://vulners.com → Account → API Keys
```

All keys are optional — any integration without a key is skipped automatically. NVD works without a key but is rate-limited to 1 request/6 seconds (vs 1/second with a key).

> **Shodan requires a paid plan.** The free API key does not include access to the host lookup endpoint (`/shodan/host/{ip}`). You need at least the [Membership plan](https://account.shodan.io/billing) for Shodan results to work.

---

## Usage

```bash
python3 recon.py <ip_address>
```

**Example:**

```bash
python3 recon.py 8.8.8.8
```

---

## What it does

| Step | Source | What you get |
|------|--------|--------------|
| 1 | **Shodan** | Open ports, banners, org/ISP/geo, Shodan-flagged CVEs |
| 2 | **Censys** | Services, TLS certificate details, ASN info |
| 3 | **Nmap** | Live port scan with service/version detection (`-sV -sC`) |
| 4 | **NVD** | CVE lookup for every detected product/service |
| 5 | **Vulners** | Additional vulnerability search across detected software |
| 6 | **Summary** | Deduplicated software list + recommended next steps |
