# Network Traffic Analysis and Threat Detection

This repository contains my SOC portfolio project analyzing HTTP requests and responses using Wireshark.  
The analysis was performed on a 3-day PCAP dataset (sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)).

## Objectives
- Demonstrate HTTP request/response analysis using Wireshark.
- Identify suspicious/malicious patterns (e.g., `.env`, AWS credential probes).
- Enrich findings with VirusTotal.
- Document Indicators of Compromise (IOCs).

## Key Findings
- Multiple `.env` and `/aws/credentials` probing attempts from different IPs.
- Malicious probing for `phpunit eval-stdin.php` and `ThinkPHP` vulnerabilities.
- Mozi botnet delivery attempt identified in HTTP POST traffic.

## Indicators of Compromise (IOCs)
| IP Address       | Behavior | VT Detection | Verdict |
|------------------|----------|--------------|---------|
| 78.153.140.179   | `.env` probing (37 requests) | 13/95 | Malicious |
| 116.196.87.121   | phpunit/ThinkPHP probes (45) | 0/95  | Suspicious |
| 87.251.78.46     | `/aws/credentials` probe     | 6/95  | Malicious |
| 193.41.206.189   | AWS credential probing       | 4/95  | Malicious |
| 217.154.112.93   | Symfony `parameters.yml`     | 0/95  | Suspicious |

## Repository Contents
- `Report.pdf` – Full project report with findings, conclusions, and recommendations.
- `screenshots/` – Supporting evidence (Wireshark captures, VirusTotal results).
- `ioc_table.csv` – Structured IOC data.

## Tools Used
- Wireshark
- VirusTotal
- Linux CLI utilities

## Author
👤 Emmanuel (SOC Analyst in training)  
- GitHub: [@emmanucodes](https://github.com/emmanucodes)  
- LinkedIn: [https://WWW.linkedin.com/in/emmanuel-ajayi-gbenga]

