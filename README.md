# Network Traffic Analysis and Threat Detection

This repository contains my SOC portfolio project analyzing HTTP requests and responses using Wireshark.  
The analysis was performed on a 3-day PCAP dataset sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net).

## Objectives
- Demonstrate HTTP request/response analysis using Wireshark.
- Identify suspicious and malicious patterns (e.g., `.env`, AWS credential probes, exploit attempts).
- Enrich findings with VirusTotal and WHOIS/IPinfo.
- Document Indicators of Compromise (IOCs) in structured format.

## Key Findings
- Multiple `.env` and `/aws/credentials` probing attempts from different IPs.
- Malicious probing for `phpunit eval-stdin.php` and `ThinkPHP` vulnerabilities.
- Attempted access to Symfony framework configuration file (`parameters.yml`).
- A Mozi botnet delivery attempt via HTTP POST traffic.

## Indicators of Compromise (IOCs)

### Malicious / Suspicious IPs
| IP Address       | Behavior Observed | VT Detection | Verdict |
|------------------|-------------------|--------------|---------|
| 78.153.140.179   | `.env` probing (37 requests) | 13/95 | Malicious |
| 116.196.87.121   | phpunit/ThinkPHP exploit probes (45) | 0/95  | Suspicious Scanning |
| 87.251.78.46     | Attempted access to `/.aws/credentials` | 6/95  | Malicious |
| 193.41.206.189   | AWS credential probing | 4/95  | Malicious |
| 217.154.112.93   | Symfony `parameters.yml` probing | 0/95  | Suspicious Scanning |

### Suspicious URIs / Endpoints
| URI / Endpoint   | Behavior / Context | Reference |
|------------------|--------------------|-----------|
| `/.env`, `/admin/.env`, `/javascript/.env` | Environment file probes (common credential targets) | MITRE ATT&CK T1552 |
| `/.aws/credentials` | Attempt to retrieve cloud credential files | MITRE ATT&CK T1552 |
| `/app_dev.php/_profiler/open?file=app/config/parameters.yml` | Symfony configuration probing | MITRE ATT&CK T1190 |
| `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` | Known exploit path for PHPUnit RCE | CVE-2017-9841 |
| `index.php?s=/Index/...invokefunction&function=call_user_func_array` | ThinkPHP remote code execution attempt | CVE-2019-9082 |
| `POST /GponForm/diag_Form?...wget Mozi.m` | Command injection delivering Mozi botnet payload | MITRE ATT&CK T1105 |

## Repository Contents
- `Report.pdf` – Full project report with findings, conclusions, and recommendations.
- `ioc_table.csv` – Structured IOC dataset (IPs and URIs).
- `screenshots/` – Supporting evidence (Wireshark captures, VirusTotal lookups).

## Tools Used
- Wireshark
- VirusTotal
- Linux CLI utilities

## Author
👤 Emmanuel (SOC Analyst in training)  
- GitHub: [@emmanucodes](https://github.com/emmanucodes)  
- LinkedIn: [https://www.linkedin.com/in/emmanuel-ajayi-gbenga](https://www.linkedin.com/in/emmanuel-ajayi-gbenga)
