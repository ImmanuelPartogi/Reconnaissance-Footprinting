# Recon Tool

A simple yet powerful reconnaissance tool for gathering essential information about a domain or host. 

## Features

- **DNS Enumeration**: Retrieve A, MX, NS, and TXT records.
- **WHOIS Information Gathering**: Gather WHOIS data to find domain registration details.
- **Port Scanning**: Scan open ports using **Nmap**.
- **HTTP Header Analysis**: Analyze HTTP headers for server details and other relevant information.
- **Basic Host Discovery**: Quickly identify active hosts on a network.

## Installation
To get started, you'll need to install the following dependencies:

```
pip install dnspython python-whois requests python-nmap
```

## Usage
Once the dependencies are installed, you can use the tool by running the following command:

```
python recon_tool.py example.com
```

Replace example.com with the domain or host you want to investigate.


## Example Output
The tool will output valuable data such as:
- **DNS records (A, MX, NS, TXT)**
- **WHOIS information**
- **Open ports and services (via Nmap)**
- **HTTP headers**
- **Active hosts**



![code](https://github.com/user-attachments/assets/39a6a38f-36c7-4b95-9288-0be02aab77b4)
