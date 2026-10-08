\# IOC Triage CLI



\[!\[Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

\[!\[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

\[!\[SOC Automation](https://img.shields.io/badge/Focus-SOC%20Triage-green.svg)]()



An asynchronous threat intelligence enrichment CLI engineered for SOC analysts and incident responders. Performs high-speed concurrent lookups against VirusTotal (v3) and AbuseIPDB with built-in RFC 1918 filtering.



\## Features

\- \*\*Async Concurrency:\*\* Executes multi-source threat intelligence checks in parallel via `httpx`.

\- \*\*Pre-flight Sanitization:\*\* Automatically ignores loopback, multicast, and RFC 1918 private IPs to conserve API quotas.

\- \*\*Rich Output:\*\* Color-coded terminal summaries with threshold-based threat scoring.

\- \*\*JSON Export:\*\* Structured outputs ready for SIEM ingestion or automated ticketing pipelines.



\## Setup \& Installation



```bash

git clone \[https://github.com/DaVinci7549/ioc-triage-cli.git](https://github.com/DaVinci7549/ioc-triage-cli.git)

cd ioc-triage-cli

python -m venv venv

.\\venv\\Scripts\\activate

pip install -r requirements.txt

cp .env.example .env

