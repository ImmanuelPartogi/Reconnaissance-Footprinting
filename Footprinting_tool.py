import socket
import requests
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from datetime import datetime
import subprocess
import re
import ssl
import sys
import os
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class WindowsReconTool:
    def __init__(self, target):
        self.target = target
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "network_info": {},
            "system_info": {},
            "organization_info": {},
            "passive_footprinting": {},
            "active_footprinting": {},
        }

    def scan_ports(self, target_ip):
        """Basic port scanner implementation"""
        print("[+] Starting basic port scan...")
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = {}

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    # Try to get service banner
                    try:
                        sock.send(b"Hello\r\n")
                        banner = sock.recv(1024).decode().strip()
                    except:
                        banner = "No banner"

                    open_ports[port] = {
                        "state": "open",
                        "service": socket.getservbyport(port, "tcp"),
                        "banner": banner,
                    }
                    print(f"[+] Port {port} is open")
                sock.close()
            except:
                continue

        return open_ports

    def collect_network_info(self):
        """Collect network information including domains, IPs, and services"""
        network_info = {}

        # Get IP and DNS information
        try:
            ip = socket.gethostbyname(self.target)
            network_info["ip_address"] = ip
            print(f"[+] Found IP address: {ip}")

            # Get DNS records
            record_types = ["A", "MX", "NS", "TXT", "SOA", "CNAME"]
            dns_records = {}
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record)
                    dns_records[record] = [str(answer) for answer in answers]
                    print(
                        f"[+] Found {record} records: {len(dns_records[record])} entries"
                    )
                except:
                    dns_records[record] = []
            network_info["dns_records"] = dns_records

            # Perform port scan
            network_info["open_ports"] = self.scan_ports(ip)

        except Exception as e:
            print(f"[-] Error collecting network information: {str(e)}")
            network_info["ip_address"] = None
            network_info["dns_records"] = {}
            network_info["open_ports"] = {}

        self.results["network_info"] = network_info
        return network_info

    def collect_system_info(self):
        """Collect system information including banners"""
        system_info = {}

        # Basic HTTP/HTTPS server information
        try:
            print("[+] Collecting web server information...")
            for protocol in ["http", "https"]:
                try:
                    response = requests.get(
                        f"{protocol}://{self.target}",
                        verify=False,
                        timeout=5,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    system_info[f"{protocol}_server"] = dict(response.headers)
                    print(f"[+] Collected {protocol.upper()} server information")
                except:
                    system_info[f"{protocol}_server"] = None
        except Exception as e:
            print(f"[-] Error collecting server information: {str(e)}")

        self.results["system_info"] = system_info
        return system_info

    def collect_org_info(self):
        """Collect organization information through various sources"""
        org_info = {}

        # WHOIS information
        try:
            print("[+] Collecting WHOIS information...")
            w = whois.whois(self.target)
            org_info["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "org": w.org,
                "emails": w.emails,
            }
            print("[+] WHOIS information collected")
        except Exception as e:
            print(f"[-] Error collecting WHOIS information: {str(e)}")
            org_info["whois"] = None

        # Website scraping
        try:
            print("[+] Scraping website information...")
            r = requests.get(
                f"https://{self.target}",
                verify=False,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            soup = BeautifulSoup(r.text, "html.parser")

            # Extract and clean email addresses
            emails = re.findall(r"[\w\.-]+@[\w\.-]+", r.text)
            cleaned_emails = [email for email in emails if self.is_valid_email(email)]

            # Extract and clean phone numbers
            phone_pattern = (
                r"(?:(?:\+|0{0,2})62|[0])?[\s-]?(?:\d{2,3})[\s-]?\d{3,4}[\s-]?\d{3,4}"
            )
            phones = re.findall(phone_pattern, r.text)
            cleaned_phones = [self.clean_phone(phone) for phone in phones]

            org_info["website"] = {
                "title": soup.title.string if soup.title else None,
                "meta_description": (
                    soup.find("meta", {"name": "description"})["content"]
                    if soup.find("meta", {"name": "description"})
                    else None
                ),
                "emails": list(set(cleaned_emails)),
                "phone_numbers": list(set(cleaned_phones)),
                "social_links": list(
                    set(
                        [
                            link.get("href")
                            for link in soup.find_all("a")
                            if any(
                                domain in str(link).lower()
                                for domain in [
                                    "linkedin.com",
                                    "facebook.com",
                                    "twitter.com",
                                    "instagram.com",
                                ]
                            )
                        ]
                    )
                ),
            }
            print("[+] Website information collected")
        except Exception as e:
            print(f"[-] Error scraping website: {str(e)}")
            org_info["website"] = None

        self.results["organization_info"] = org_info
        return org_info

    def is_valid_email(self, email):
        """Validate email address format"""
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return bool(re.match(pattern, email))

    def clean_phone(self, phone):
        """Clean and format phone numbers"""
        # Remove non-numeric characters
        cleaned = re.sub(r"[^\d+]", "", phone)
        # Format Indonesian numbers
        if cleaned.startswith("62"):
            return "+" + cleaned
        elif cleaned.startswith("0"):
            return "+62" + cleaned[1:]
        return cleaned

    def passive_footprinting(self):
        """Perform passive footprinting"""
        passive_info = {}

        # SSL certificate information
        try:
            print("[+] Collecting SSL certificate information...")
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    passive_info["ssl_cert"] = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": cert["version"],
                        "serialNumber": cert["serialNumber"],
                        "notBefore": cert["notBefore"],
                        "notAfter": cert["notAfter"],
                    }
            print("[+] SSL certificate collected")
        except Exception as e:
            print(f"[-] Error collecting SSL certificate: {str(e)}")
            passive_info["ssl_cert"] = None

        self.results["passive_footprinting"] = passive_info
        return passive_info

    def active_footprinting(self):
        """Perform active footprinting"""
        active_info = {}

        # Simple ping test
        try:
            print("[+] Performing ping test...")
            ping_param = "-n" if sys.platform.startswith("win") else "-c"
            result = subprocess.run(
                ["ping", ping_param, "1", self.target],
                capture_output=True,
                text=True,
                timeout=10,
            )
            active_info["ping_test"] = result.stdout
            print("[+] Ping test completed")
        except Exception as e:
            print(f"[-] Error during ping test: {str(e)}")
            active_info["ping_test"] = None

        self.results["active_footprinting"] = active_info
        return active_info

    def run_all_checks(self):
        """Run all reconnaissance and footprinting checks"""
        print(f"\n[*] Starting reconnaissance on {self.target}")
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self.collect_network_info)
            executor.submit(self.collect_system_info)
            executor.submit(self.collect_org_info)
            executor.submit(self.passive_footprinting)
            executor.submit(self.active_footprinting)

        return self.results

    def save_results(self):
        """Save results to JSON file"""
        filename = (
            f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] Results saved to {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(
        description="Windows-Compatible Reconnaissance Tool"
    )
    parser.add_argument("target", help="Target domain or IP address")
    args = parser.parse_args()

    recon = WindowsReconTool(args.target)
    results = recon.run_all_checks()
    filename = recon.save_results()


if __name__ == "__main__":
    main()
