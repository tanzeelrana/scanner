#!/usr/bin/env python3
"""
Network Reconnaissance & Vulnerability Scanner
Combines Shodan, Censys, NVD, Vulners, and Nmap for comprehensive analysis
Usage: python3 recon.py <ip_address>
"""

import sys
import time
import subprocess
import requests
from base64 import b64encode

# ─────────────────────────────────────────────
#  API KEYS — replace with your actual keys
# ─────────────────────────────────────────────
SHODAN_API_KEY    = "YOUR_SHODAN_API_KEY_HERE"      # https://shodan.io
NVD_API_KEY       = "YOUR_NVD_API_KEY_HERE"         # https://nvd.nist.gov/developers/request-an-api-key
CENSYS_API_ID     = "YOUR_CENSYS_API_ID_HERE"       # https://censys.io → Account → API
CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET_HERE"
VULNERS_API_KEY   = "YOUR_VULNERS_API_KEY_HERE"     # https://vulners.com → Account → API Keys
# ─────────────────────────────────────────────


def banner():
    print("""
╔══════════════════════════════════════════════════════╗
║         Network Recon & Vulnerability Scanner        ║
║         For authorized security research only        ║
╚══════════════════════════════════════════════════════╝
""")


def section(title):
    print(f"\n{'═' * 54}")
    print(f"  {title}")
    print(f"{'═' * 54}")


# ─────────────────────────────────────────────
#  SHODAN
# ─────────────────────────────────────────────
def run_shodan(ip):
    section("SHODAN RESULTS")

    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        print("  [!] Shodan API key not set — skipping")
        return []

    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
            timeout=15
        )

        if response.status_code == 401:
            print("  [!] Invalid Shodan API key")
            return []
        if response.status_code == 404:
            print("  [!] IP not found in Shodan database")
            return []
        if response.status_code != 200:
            print(f"  [!] Shodan error: HTTP {response.status_code}")
            return []

        data = response.json()

        print(f"  IP Address   : {data.get('ip_str', ip)}")
        print(f"  Organization : {data.get('org', 'N/A')}")
        print(f"  ISP          : {data.get('isp', 'N/A')}")
        print(f"  Country      : {data.get('country_name', 'N/A')}")
        print(f"  City         : {data.get('city', 'N/A')}")
        print(f"  Last Updated : {data.get('last_update', 'N/A')}")

        hostnames = data.get('hostnames', [])
        if hostnames:
            print(f"  Hostnames    : {', '.join(hostnames)}")

        ports = data.get('ports', [])
        if ports:
            print(f"\n  Open Ports   : {', '.join(map(str, ports))}")

        services = data.get('data', [])
        software_list = []

        if services:
            print(f"\n  ── Service Details ──")
            for svc in services:
                port      = svc.get('port', 'N/A')
                transport = svc.get('transport', 'tcp')
                product   = svc.get('product', '')
                version   = svc.get('version', '')
                cpes      = svc.get('cpe', [])
                b         = svc.get('banner', '').strip()

                print(f"\n    Port    : {port}/{transport}")
                if product:
                    print(f"    Product : {product} {version}".strip())
                    software_list.append({"product": product, "version": version})
                if cpes:
                    print(f"    CPE     : {', '.join(cpes)}")
                if b:
                    print(f"    Banner  : {b[:120]}")

        vulns = data.get('vulns', [])
        if vulns:
            print(f"\n  ── Shodan Flagged CVEs ──")
            for cve in vulns:
                print(f"    [!] {cve}")

        return software_list

    except requests.exceptions.ConnectionError:
        print("  [!] Could not connect to Shodan API")
        return []
    except Exception as e:
        print(f"  [!] Shodan error: {e}")
        return []


# ─────────────────────────────────────────────
#  CENSYS
# ─────────────────────────────────────────────
def run_censys(ip):
    section("CENSYS RESULTS")

    if CENSYS_API_ID == "YOUR_CENSYS_API_ID_HERE":
        print("  [!] Censys API credentials not set — skipping")
        return []

    try:
        credentials = b64encode(
            f"{CENSYS_API_ID}:{CENSYS_API_SECRET}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        }

        response = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 401:
            print("  [!] Invalid Censys API credentials")
            return []
        if response.status_code == 404:
            print("  [!] IP not found in Censys database")
            return []
        if response.status_code == 429:
            print("  [!] Censys rate limit reached")
            return []
        if response.status_code != 200:
            print(f"  [!] Censys error: HTTP {response.status_code}")
            return []

        data = response.json().get("result", {})
        software_list = []

        print(f"  IP Address   : {data.get('ip', ip)}")

        asn = data.get("autonomous_system", {})
        if asn:
            print(f"  ASN          : {asn.get('asn', 'N/A')}")
            print(f"  AS Name      : {asn.get('name', 'N/A')}")
            print(f"  BGP Prefix   : {asn.get('bgp_prefix', 'N/A')}")
            print(f"  Country Code : {asn.get('country_code', 'N/A')}")

        location = data.get("location", {})
        if location:
            print(f"  Location     : {location.get('city', 'N/A')}, {location.get('country', 'N/A')}")

        services = data.get("services", [])
        if services:
            print(f"\n  ── Services Detected ──")
            for svc in services:
                port         = svc.get("port", "N/A")
                transport    = svc.get("transport_protocol", "tcp").lower()
                service_name = svc.get("service_name", "N/A")
                extended     = svc.get("extended_service_name", "")
                sw_list      = svc.get("software", [])
                tls          = svc.get("tls", {})

                print(f"\n    Port    : {port}/{transport}")
                print(f"    Service : {service_name}" +
                      (f" ({extended})" if extended and extended != service_name else ""))

                for sw in sw_list:
                    p = sw.get("product", "")
                    v = sw.get("version", "")
                    if p:
                        print(f"    Software: {p} {v}".strip())
                        software_list.append({"product": p, "version": v})

                if tls:
                    cert = tls.get("certificates", {}).get("leaf_data", {})
                    subject = cert.get("subject_dn", "")
                    issuer  = cert.get("issuer_dn", "")
                    if subject:
                        print(f"    TLS Subj: {subject[:80]}")
                    if issuer:
                        print(f"    TLS Issu: {issuer[:80]}")

        last_updated = data.get("last_updated_at", "N/A")
        print(f"\n  Last Updated : {last_updated[:10] if last_updated != 'N/A' else 'N/A'}")

        return software_list

    except requests.exceptions.ConnectionError:
        print("  [!] Could not connect to Censys API")
        return []
    except Exception as e:
        print(f"  [!] Censys error: {e}")
        return []


# ─────────────────────────────────────────────
#  NMAP
# ─────────────────────────────────────────────
def run_nmap(ip):
    section("NMAP RESULTS")

    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  [!] nmap not installed or not in PATH")
        print("      Install: sudo apt install nmap  (Linux)")
        print("               brew install nmap      (macOS)")
        return []

    print(f"  Running nmap scan on {ip} — this may take a moment...\n")

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-sC", "-T4", "--open", ip],
            capture_output=True, text=True, timeout=120
        )

        output = result.stdout
        if output:
            for line in output.splitlines():
                print(f"  {line}")
        else:
            print("  [!] No nmap output returned")

        software_list = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 4:
                    product = parts[3] if len(parts) > 3 else ""
                    version = parts[4] if len(parts) > 4 else ""
                    if product and product not in ("open", "filtered"):
                        software_list.append({"product": product, "version": version})

        return software_list

    except subprocess.TimeoutExpired:
        print("  [!] nmap scan timed out")
        return []
    except Exception as e:
        print(f"  [!] nmap error: {e}")
        return []


# ─────────────────────────────────────────────
#  NVD CVE LOOKUP
# ─────────────────────────────────────────────
def lookup_nvd(software_list):
    section("NVD CVE LOOKUP")

    if not software_list:
        print("  [!] No software detected to look up")
        return

    headers = {}
    if NVD_API_KEY and NVD_API_KEY != "YOUR_NVD_API_KEY_HERE":
        headers["apiKey"] = NVD_API_KEY

    seen = set()
    for software in software_list:
        product = software.get("product", "").strip()
        version = software.get("version", "").strip()

        if not product or product in seen:
            continue
        seen.add(product)

        print(f"\n  Searching NVD for: {product} {version}".strip())
        print(f"  {'─' * 48}")

        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": product, "resultsPerPage": 5},
                headers=headers,
                timeout=15
            )

            if response.status_code == 403:
                print("  [!] NVD rate limit — add API key for higher limits")
                continue
            if response.status_code != 200:
                print(f"  [!] NVD error: HTTP {response.status_code}")
                continue

            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            if not vulns:
                print("    No CVEs found")
                continue

            print(f"    Total CVEs in NVD: {total} (showing top 5)")

            for item in vulns:
                cve       = item.get("cve", {})
                cve_id    = cve.get("id", "N/A")
                published = cve.get("published", "N/A")[:10]

                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description available"
                )

                score    = "N/A"
                severity = "N/A"
                metrics  = cve.get("metrics", {})

                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric = metrics.get(key, [])
                    if metric:
                        score    = metric[0]["cvssData"]["baseScore"]
                        severity = metric[0]["cvssData"].get(
                            "baseSeverity", metric[0].get("baseSeverity", "N/A")
                        )
                        break

                print(f"\n    CVE       : {cve_id}")
                print(f"    Published : {published}")
                print(f"    CVSS      : {score} ({severity})")
                print(f"    Summary   : {desc[:200]}")
                print(f"    Link      : https://nvd.nist.gov/vuln/detail/{cve_id}")

            time.sleep(1 if NVD_API_KEY != "YOUR_NVD_API_KEY_HERE" else 6)

        except requests.exceptions.ConnectionError:
            print("  [!] Could not connect to NVD API")
        except Exception as e:
            print(f"  [!] NVD error: {e}")


# ─────────────────────────────────────────────
#  VULNERS
# ─────────────────────────────────────────────
def lookup_vulners(software_list):
    section("VULNERS CVE LOOKUP")

    if VULNERS_API_KEY == "YOUR_VULNERS_API_KEY_HERE":
        print("  [!] Vulners API key not set — skipping")
        return

    if not software_list:
        print("  [!] No software detected to look up")
        return

    seen = set()
    for software in software_list:
        product = software.get("product", "").strip()
        version = software.get("version", "").strip()

        if not product or product in seen:
            continue
        seen.add(product)

        query = f"{product} {version}".strip()
        print(f"\n  Searching Vulners for: {query}")
        print(f"  {'─' * 48}")

        try:
            response = requests.post(
                "https://vulners.com/api/v3/search/lucene/",
                json={
                    "query":  query,
                    "fields": ["id", "cvss", "title", "description",
                               "published", "type", "href"],
                    "size":   5,
                    "apiKey": VULNERS_API_KEY
                },
                timeout=15
            )

            if response.status_code == 401:
                print("  [!] Invalid Vulners API key")
                return
            if response.status_code == 429:
                print("  [!] Vulners rate limit reached")
                return
            if response.status_code != 200:
                print(f"  [!] Vulners error: HTTP {response.status_code}")
                continue

            data    = response.json()
            results = data.get("data", {}).get("search", [])
            total   = data.get("data", {}).get("total", 0)

            if not results:
                print("    No results found in Vulners")
                continue

            print(f"    Total results in Vulners: {total} (showing top 5)")

            for item in results:
                src        = item.get("_source", {})
                vuln_id    = src.get("id", "N/A")
                title      = src.get("title", "N/A")
                published  = src.get("published", "N/A")[:10]
                cvss_score = src.get("cvss", {}).get("score", "N/A")
                desc       = src.get("description", "")
                href       = src.get("href", "")
                vtype      = src.get("type", "N/A")

                print(f"\n    ID          : {vuln_id}")
                print(f"    Type        : {vtype}")
                print(f"    Title       : {title[:100]}")
                print(f"    Published   : {published}")
                print(f"    CVSS Score  : {cvss_score}")
                if desc:
                    print(f"    Description : {desc[:200]}")
                if href:
                    print(f"    Link        : {href}")

            time.sleep(1)

        except requests.exceptions.ConnectionError:
            print("  [!] Could not connect to Vulners API")
        except Exception as e:
            print(f"  [!] Vulners error: {e}")


# ─────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────
def print_summary(ip, all_software):
    section("SUMMARY")
    print(f"  Target IP : {ip}")

    seen   = set()
    unique = []
    for s in all_software:
        key = f"{s['product']}_{s['version']}"
        if key not in seen and s["product"]:
            seen.add(key)
            unique.append(s)

    if unique:
        print(f"\n  Software / Services Detected:")
        for s in unique:
            print(f"    - {s['product']} {s['version']}".strip())

    print(f"\n  Recommended Next Steps:")
    print(f"    1. Review all CVEs above and check your affected versions")
    print(f"    2. Patch or update any outdated services immediately")
    print(f"    3. Disable any services that don't need to be publicly exposed")
    print(f"    4. Re-run this scan after patching to verify changes")
    print(f"    5. Set up Shodan Monitor alerts on this IP for ongoing monitoring")
    print()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    banner()

    if len(sys.argv) != 2:
        print("Usage: python3 recon.py <ip_address>")
        print("Example: python3 recon.py 203.0.113.10")
        sys.exit(1)

    ip = sys.argv[1].strip()
    print(f"  Target    : {ip}")
    print(f"  Starting reconnaissance...\n")

    shodan_software = run_shodan(ip)
    censys_software = run_censys(ip)
    nmap_software   = run_nmap(ip)

    all_software = shodan_software + censys_software + nmap_software

    lookup_nvd(all_software)
    lookup_vulners(all_software)
    print_summary(ip, all_software)


if __name__ == "__main__":
    main()