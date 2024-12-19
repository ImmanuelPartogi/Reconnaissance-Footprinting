# Reconnaissance / Footprinting

A powerful reconnaissance tool designed to gather information about target domains and websites. Built specifically for Windows, this tool operates independently without requiring external tools and employs various footprinting techniques, both passive and active.

---

## 🚀 Features

### 🔍 Main Functions

#### a) `scan_ports()`
- Performs basic port scanning (21, 22, 23, 25, 80, 443, etc.).
- Attempts to retrieve banners from open ports.
- Identifies running services.

#### b) `collect_network_info()`
- Collects the target's IP address.
- Retrieves DNS records (A, MX, NS, TXT, SOA, CNAME).
- Conducts port scanning.

#### c) `collect_system_info()`
- Collects HTTP/HTTPS server information.
- Retrieves the server's response headers.

#### d) `collect_org_info()`
- Gathers WHOIS data of the domain.
- Performs web scraping to collect:
  - Email addresses.
  - Phone numbers.
  - Social media links.
  - Website metadata.

#### e) `passive_footprinting()`
- Collects SSL certificate information.
- Does not make direct connections to the target.

#### f) `active_footprinting()`
- Performs ping tests to the target.
- Directly interacts with the target.

---

## 🌟 Additional Features
- **Email Format Validation:** Ensures proper email formatting.
- **Phone Number Format Cleaning:** Optimized for Indonesian numbers.
- **JSON Output:** Stores all results in JSON format.
- **Multi-threading:** Executes tasks in parallel for improved efficiency.
- **Comprehensive Error Handling:** Ensures robust execution and provides clear error messages.

---

## 📂 Output
- Saves all results in a structured JSON file.
- Displays real-time progress.
- Provides detailed error messages in case of failures.

---

## 🔒 Security Features
- Disables SSL warnings to enhance compatibility.
- Utilizes a browser User-Agent for HTTP requests.
- Implements connection timeouts to prevent hanging.

---

## 📦 Required Dependencies
To use this tool, ensure the following Python libraries are installed:
- **dnspython:** For DNS queries.
- **python-whois:** For WHOIS data retrieval.
- **requests:** For HTTP requests.
- **beautifulsoup4:** For HTML parsing.

Install them using:
```
pip install dnspython python-whois requests beautifulsoup4
```

---
## 💼 Use Cases
This tool is designed for ethical information gathering and is ideal for:
- **Security audits.**
- **Penetration testing.**
- **Infrastructure analysis.**
- **Domain investigations.**

---
## 🛠️ How to Use
- Clone this repository to your local machine:
- Install the required dependencies.
- Run the tool and follow the on-screen instructions.
- View results in the generated JSON file.

run:
```
python Footprinting_tool.py example.com
```

---
## ⚠️ Disclaimer
This tool is intended for ethical use only. Ensure you have proper authorization before performing any reconnaissance activities. Unauthorized use may violate applicable laws and regulations.

---
Thank you for using Recon Tool! Happy auditing! 🎉
