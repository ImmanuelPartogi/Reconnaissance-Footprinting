import socket
import requests
import dns.resolver
import whois
import nmap
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from datetime import datetime

class ReconTool:
    def __init__(self, target):
        self.target = target
        self.results = {}
        
    def get_ip(self):
        """Get IP address for target domain"""
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip'] = ip
            return ip
        except socket.gaierror:
            return "Could not resolve hostname"
            
    def get_dns_records(self):
        """Get various DNS records"""
        record_types = ['A', 'MX', 'NS', 'TXT']
        dns_results = {}
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record)
                dns_results[record] = [str(answer) for answer in answers]
            except:
                dns_results[record] = []
                
        self.results['dns_records'] = dns_results
        return dns_results
        
    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            w = whois.whois(self.target)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
            return self.results['whois']
        except:
            return "WHOIS lookup failed"
            
    def scan_common_ports(self):
        """Scan most common ports using nmap"""
        nm = nmap.PortScanner()
        try:
            nm.scan(self.target, arguments='-F -sT')
            self.results['port_scan'] = nm[self.target]['tcp']
            return self.results['port_scan']
        except:
            return "Port scan failed"
            
    def check_http_headers(self):
        """Get HTTP headers from web server"""
        try:
            r = requests.head(f"http://{self.target}", timeout=5)
            self.results['http_headers'] = dict(r.headers)
            return self.results['http_headers']
        except:
            try:
                r = requests.head(f"https://{self.target}", timeout=5)
                self.results['http_headers'] = dict(r.headers)
                return self.results['http_headers']
            except:
                return "Could not retrieve HTTP headers"
                
    def run_all_checks(self):
        """Run all reconnaissance checks"""
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self.get_ip)
            executor.submit(self.get_dns_records)
            executor.submit(self.get_whois_info)
            executor.submit(self.scan_common_ports)
            executor.submit(self.check_http_headers)
            
        return self.results
        
    def save_results(self):
        """Save results to JSON file"""
        filename = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        return filename

def main():
    parser = argparse.ArgumentParser(description='Basic Reconnaissance Tool')
    parser.add_argument('target', help='Target domain or IP address')
    args = parser.parse_args()
    
    recon = ReconTool(args.target)
    print(f"Starting reconnaissance on {args.target}...")
    results = recon.run_all_checks()
    filename = recon.save_results()
    print(f"Reconnaissance complete. Results saved to {filename}")
    
if __name__ == "__main__":
    main()