# SecScan AppSec Suite

[Português](README.md) · **English**

This file is the English README. The Portuguese version is [README.md](README.md).

[![Node.js 22](https://img.shields.io/badge/Node.js-22%20LTS-339933?logo=nodedotjs&logoColor=white)](package.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Standard-4B32C3?logo=github&logoColor=white)](https://sarifweb.azurewebsites.net/)
[![References OWASP, CWE, and Snyk Learn](https://img.shields.io/badge/References-OWASP%20%7C%20CWE%20%7C%20Snyk%20Learn-00FF41)](https://owasp.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**SecScan runs on your machine.** You download the code, start the local server, and analyze files there. The report (findings, quality gate, SARIF, suggested fixes) comes out of that process. Docker is not required. Publishing the site is not required for a scan to work.

The step-by-step tutorial is in [docs/local-use.md](docs/local-use.md). The Portuguese tutorial is in [docs/uso-local.md](docs/uso-local.md).

Code you paste or upload is scanned in the browser. URL audit, the on-disk `.gitignore` listing, and model-written mitigation go through Express at `http://localhost:3000`. Screens badged **LAB** (Nmap, Nikto, EDR, firewall, DNS, SD-WAN, SOC, CrowdStrike, Security Onion, SOAR, IAST, DAST, and threat intel) show a sample scenario. A static site (Vercel or GitHub Pages) only serves the interface. The `/api` routes do not answer there.

## Run it on your machine

You need Node.js 22 and npm. No Docker image, no database, no Vercel account.

```bash
git clone https://github.com/saulofilho/secscan.git
cd secscan
node -v          # v22.x
npm install
npm run dev      # http://localhost:3000
```

Leave `SECSCAN_API_TOKEN` unset. The interface does not send that header. `GEMINI_API_KEY` in `.env` is optional: without it, mitigation uses the local engine.

`npm run dev` runs `tsx server.ts`. That process serves the page and the `/api` routes. When the terminal prints `SecScan AppSec Suite Server running on port 3000`, open [http://localhost:3000](http://localhost:3000). `Ctrl+C` stops it.

On the entry page, load the demo project or upload your own files. The progress bar reaches 100% in the browser. The footer states that this is a test tool.

`POST /api/url-ingest` refuses localhost, cloud metadata, private networks, and redirects to those destinations. The CLI also runs on the machine, with Node 22 and the dependencies installed:

```bash
node bin/secscan.js .
node bin/secscan.js . --max-risk 50
node bin/secscan.js . --fail-on critical
node bin/secscan.js . --format sarif --output secscan-results.sarif
```

The CLI reads `src/lib/defaultRules.ts`, the same default rules as the interface. It does not need the server on port 3000. It does need `npm install`.

## What runs where

| Action | Where it runs |
|---|---|
| Paste or upload code, findings, quality gate, graph, SARIF | Browser |
| Audit a public URL | Local Express |
| List the on-disk `.gitignore` | Local Express, localhost only |
| Gemini mitigation | Local Express, when `GEMINI_API_KEY` is set |
| Mitigation without that key | Local rule engine |
| OSV package lookup | Browser, to `api.osv.dev` |
| LAB screens | Sample scenario |
| `node bin/secscan.js` | Terminal, on the folder you pass |

The quality gate score is `100 × (1 − e^(−raw/50))`. Critical counts 25, high 15, medium 6, low 2, info 0.5. Zero findings score 0. `--max-risk` exits 1 when the score is above the limit.

## Three drawers

**Your code.** Scanner, entropy, routes, JS Miner, graph, SCA, IaC, headers, JWT, SSRF classifier, Dockerfile, IAM policy, and remediation. IAST is not in this drawer.

**Laboratory.** IAST, DAST, Nmap, Nikto, WAF, NGFW, IDS, DNS, SD-WAN, EDR, SOC, Security Onion, CrowdStrike, SOAR, threat intel, and the Pro suite. The badge is `LAB`. The scenario is an example. IAST applies sample payloads to code excerpts. It does not install an agent in the process.

**Governance.** Dashboard, compliance, OPA, SBOM, quality gate, rules, CLI, and CI.

SCA reads `package.json` and `requirements.txt`, then asks OSV for names and versions. If OSV does not answer, the result stays on the local catalog and a missing package stays `NOT_IN_CATALOG`.

## Longer notes

Module-by-module notes in Portuguese (risk score, compliance, SCA, IaC, the LAB screens, and the CLI flags) are in [README.md](README.md). The English walkthrough, including what to do when port 3000 is busy, is in [docs/local-use.md](docs/local-use.md).

*SecScan AppSec Suite • Static analysis on your machine, with references to OWASP, CWE, and Snyk Learn.*
