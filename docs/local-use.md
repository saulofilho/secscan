# Run SecScan on your machine

SecScan is a local tool. You download the code, start a server on your machine, and analyze files there. The report stays with you: findings, the quality gate, SARIF, and suggested fixes.

Docker is not part of this install. There is no image, no `Dockerfile`, and no `docker compose` file. The process needs Node.js 22 and npm.

A published site (Vercel or GitHub Pages) only shows the interface. URL audit and the on-disk `.gitignore` listing answer when this machine's Express process is running.

## What you will have at the end

1. The interface open at `http://localhost:3000`.
2. A scan of a file you uploaded, or of the demo project.
3. The same modules in the terminal, without opening a browser, if you stop after `npm install` and use the CLI.

## What must already be installed

| Program | Version | Why |
|---|---|---|
| Node.js | 22 | Runs the server and the CLI |
| npm | the one shipped with Node 22 | Installs this repo's dependencies |
| Git | any recent version | Clones the code |
| A browser | current Chrome, Firefox, or Edge | Opens the interface |

Check Node before you continue:

```bash
node -v
npm -v
```

The first line must start with `v22`. If it prints `v18` or `v20`, `npm run dev` can fail because the project uses Node 22 APIs. Install 22 from [nodejs.org](https://nodejs.org/) or from the version manager you already use (`nvm`, `fnm`, `volta`).

Docker, a database, Redis, and a Vercel account are not required.

## What runs where

| Action | Where it runs |
|---|---|
| Paste or upload code, read a finding, quality gate, graph, SARIF | In the browser |
| Audit a public URL | On the local Express server (`POST /api/url-ingest`) |
| List the on-disk `.gitignore` | On the local Express server, and only from localhost |
| A mitigation written by Gemini | On the local Express server, if `GEMINI_API_KEY` is set |
| A mitigation without that key | On the local rule engine, in the page itself |
| A package lookup against OSV | In the browser, directly to `api.osv.dev` |
| Screens badged LAB | A sample scenario. They do not scan a network, a host, or a console |
| `node bin/secscan.js list` and `node bin/secscan.js <module>` | In the terminal. The server on port 3000 is not required |

## 1. Download the code

```bash
git clone https://github.com/saulofilho/secscan.git
cd secscan
```

The following commands start from that folder. The server reads disk from the directory where you ran `npm run dev`. If you start it from another folder, the `.gitignore` listing looks at the wrong place.

## 2. Install the dependencies

```bash
npm install
```

This creates `node_modules` and downloads Express, Vite, React, and the rest declared in `package.json`. The first run can take a minute. At the end, npm prints the package tree and returns to the prompt, with no `ERR!`.

If the repo already has `package-lock.json` and you want the same tree the CI job uses:

```bash
npm ci
```

`npm ci` deletes `node_modules` and reinstalls exactly what the lockfile pins. Use it when a previous install stopped halfway.

## 3. Start the interface

```bash
npm run dev
```

That script runs `tsx server.ts`. The process does two jobs at once: it serves the interface and it answers the `/api` routes.

When it is ready, the terminal prints a line in this shape:

```text
SecScan AppSec Suite Server running on port 3000
```

Open [http://localhost:3000](http://localhost:3000). The SecScan entry page appears. Leave this terminal open. `Ctrl+C` stops the server, and the page stops answering.

If port 3000 is already taken, the process exits with `EADDRINUSE`. Close the other program using that port, or stop the earlier `npm run dev` that is still running.

## 4. Run the first scan in the interface

1. On the entry page, choose the demo project if you want an example that is already filled in. To analyze your own code, enter the app and send files through the workspace file picker.
2. Wait until the progress bar reaches 100%. The scan of the text on screen happens in the browser. It does not send that code to an external service.
3. Open the dashboard. The **Risk Score** is a number from 0 to 100. Zero findings leave the score at 0. The formula is `100 × (1 − e^(−points/50))`, with critical worth 25, high 15, medium 6, low 2, and info 0.5.
4. The footer says this is a test tool and that laboratory screens use a sample scenario. That sentence is part of the product.

`.env` files, `.pem` files, and private keys are refused on upload. SecScan does not want a real secret dropped into the analysis area.

## 5. What each area does in this local mode

**Your code.** Scanner, entropy, routes, JS Miner, the graph, SCA, IaC, headers, JWT, the SSRF classifier, Dockerfile, IAM policy, and remediation. The result comes from the files in the workspace.

**Laboratory.** IAST, DAST, Nmap, Nikto, WAF, firewall, DNS, SD-WAN, EDR, SOC, and threat intel. The badge is LAB. The screen opens, the scenario is fixed, and no packet leaves the machine to scan a target. The terminal prints that same scenario. Section 7 has the command for each one.

**URL audit.** You provide a public `https://` address. Express on your machine fetches the page, refuses localhost, private IP ranges, cloud metadata, and redirects to those destinations, then returns the extracted files to the workspace. This works only while `npm run dev` (or `npm start`) is running. On the static site, the screen says the route is not up.

**SCA.** The screen reads `package.json` and `requirements.txt` from the workspace. The browser then asks OSV for each package name and version. If OSV answers, advisories join the report and the license stays the one from the local catalog. If the lookup fails, the result stays on that catalog and a missing package remains `NOT_IN_CATALOG`.

**On-disk `.gitignore`.** The disk tab lists files from the folder where `npm run dev` was started, and it only accepts the call from localhost. Do not set `SECSCAN_API_TOKEN` for local use: the interface does not send that header, and the `/api` routes would answer 401.

## 6. A Gemini key, if you want one

Mitigation works without a key, on the deterministic engine. To ask Gemini for wording:

```bash
cp .env.example .env
```

In `.env`, fill in only this line:

```bash
GEMINI_API_KEY=your-key
```

Save, stop the server with `Ctrl+C`, and start it again with `npm run dev`. `server.ts` reads that file at startup. The key stays in the local process. Do not commit `.env`.

The ad slots (`VITE_ADSENSE_CLIENT_ID` and `VITE_ADSENSE_SLOT_ID`) can stay empty. Empty, the interface draws no banner.

## 7. A terminal workspace, without the interface

This section does not use the server on port 3000. `npm install` is enough: the launcher calls the `tsx` binary in `node_modules`.

Inside the SecScan repo:

```bash
node bin/secscan.js list
```

The list has one command per module, in the five groups of the interface: code, API, cloud, SOC, and governance. The name shown on screen also works (`scanner`, `jwtinspector`, `ssrfvalidator`, `containerscan`, `cloudiam`).

From another folder, point at the launcher and the target:

```bash
node /path/to/secscan/bin/secscan.js /path/to/the/project
```

### A code folder

With no target, the current directory is used. `node bin/secscan.js .` and `node bin/secscan.js scan .` apply the rules in `src/lib/defaultRules.ts`.

```bash
node bin/secscan.js dataflow .
node bin/secscan.js jsminer .
node bin/secscan.js apisecurity .
node bin/secscan.js iast .
node bin/secscan.js dast .
node bin/secscan.js sca .
node bin/secscan.js iac .
node bin/secscan.js entropy .
node bin/secscan.js endpoints .
node bin/secscan.js sbom .
node bin/secscan.js compliance .
node bin/secscan.js dashboard .
node bin/secscan.js autoremediation .
node bin/secscan.js refactoring .
node bin/secscan.js threatmodel .
node bin/secscan.js policyascode .
node bin/secscan.js frameworks .
node bin/secscan.js pipelineflow .
```

`sca` reads `package.json` and `requirements.txt` and does not call OSV. A missing license stays `NOT_IN_CATALOG`. `sbom` builds CycloneDX and says the hashes are placeholders, not file digests. `autoremediation` and `refactoring` print the patch and leave the files unchanged. `iast` reads the local code and does not send traffic. `dast` lists routes found in the code and also does not send a request.

### One file, one token, or one URL

```bash
node bin/secscan.js dockerfile ./Dockerfile
node bin/secscan.js iam ./policy.json
node bin/secscan.js headers ./response.txt
node bin/secscan.js jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
node bin/secscan.js ssrf "http://169.254.169.254/"
node bin/secscan.js llmsecurity ./prompt.txt
```

`headers` reads `Name: value` lines and skips an `HTTP/` status line. `ssrf` classifies the URL and does not send a request. `llmsecurity` classifies the prompt text. A path argument is read as a file. A sentence is classified as text. With neither, the command exits 1.

### Laboratory scenario

These commands repeat the screen. The first line says so. They do not scan a network, a host, a feed, or a console.

```bash
node bin/secscan.js nmap
node bin/secscan.js nikto
node bin/secscan.js waf
node bin/secscan.js ngfw
node bin/secscan.js idsips
node bin/secscan.js dnssec
node bin/secscan.js sdwan
node bin/secscan.js edr
node bin/secscan.js soarbuilder
node bin/secscan.js procyber
node bin/secscan.js ctihub
node bin/secscan.js crowdstrike .
node bin/secscan.js soccommand .
node bin/secscan.js securityonion .
```

`ctihub` reads the local catalog. `node bin/secscan.js ctihub log4j` looks up that term in the catalog. `soccommand` and `securityonion` build the queue from findings in the folder. `crowdstrike` shows the sample hosts from the screen when the folder has files. `procyber --file ./artifact.txt` classifies that file in the artifact panel and stays on the sample scenario.

The table is the summary. `--format json` writes the object. `--output file` writes to disk instead of the terminal.

### Quality gate

This applies to `scan`. The score matches the interface: `100 × (1 − e^(−points/50))`, with critical 25, high 15, medium 6, low 2, and info 0.5. Zero findings leave the score at 0.

```bash
node bin/secscan.js . --max-risk 50
node bin/secscan.js . --fail-on critical
node bin/secscan.js . --format sarif --output secscan-results.sarif
```

`--max-risk` exits 1 when the score passes the limit. `--fail-on critical` (or `high`, or `medium`) exits 1 when a finding of that severity exists. `sarif` and `csv` apply to `scan`. The other modules accept `table` and `json`.

`--ignore` takes comma-separated fragments, for example `tests/,docs/`. `--rules file.json` adds a list of extra rules on `scan` and `compliance`. `--help` shows the scan options.

## 8. Stop and start again

In the server terminal, press `Ctrl+C`. To come back:

```bash
npm run dev
```

`npm start` is the other path: `npm run build` writes `dist/`, and `npm start` runs `dist/server.cjs`. Use that when you want production mode on the same machine. For day-to-day work, `npm run dev` is enough.

## When something does not open

**`node -v` is not 22.** Switch Node and open a new terminal before `npm install`.

**`npm run dev` exits immediately.** Read the last line. `EADDRINUSE` means port 3000 is taken. `Cannot find module` means `npm install` did not finish in this folder.

**The page opens and URL audit says it needs the server.** The address is not `localhost:3000`, or the `npm run dev` terminal was already closed. The static site does not run that route.

**Mitigation does not mention Gemini.** `GEMINI_API_KEY` is missing from `.env`, or the server was not restarted after the file was saved. The page still shows the local engine's fix.
