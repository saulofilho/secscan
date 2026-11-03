# Run SecScan on your machine

SecScan is a local tool. You download the code, start a server on your machine, and analyze files there. The report stays with you: findings, the quality gate, SARIF, and suggested fixes.

Docker is not part of this install. There is no image, no `Dockerfile`, and no `docker compose` file. The process needs Node.js 22 and npm.

A published site (Vercel or GitHub Pages) only shows the interface. URL audit and the on-disk `.gitignore` listing answer when this machine's Express process is running.

## What you will have at the end

1. The interface open at `http://localhost:3000`.
2. A scan of a file you uploaded, or of the demo project.
3. A terminal report, if you point the CLI at a folder on disk.

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
| `node bin/secscan.js` | In the terminal, against the folder you pass |

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

**Laboratory.** IAST, DAST, Nmap, Nikto, WAF, firewall, DNS, SD-WAN, EDR, SOC, and threat intel. The badge is LAB. The screen opens, the scenario is fixed, and no packet leaves the machine to scan a target.

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

## 7. A scan from the terminal

The CLI uses the same default rules as the interface (`src/lib/defaultRules.ts`). It reads files from disk. It does not open a browser and it does not need the server on port 3000. It still needs `npm install`, because the launcher uses the `tsx` installed in the project.

From a folder you want to audit:

```bash
node /path/to/secscan/bin/secscan.js .
```

Inside the SecScan repo itself, the current folder is the target:

```bash
node bin/secscan.js .
```

That command, and the equivalent `node bin/secscan.js scan .`, applies the static rules. For one engine:

```bash
node bin/secscan.js sca .
node bin/secscan.js iac .
node bin/secscan.js entropy .
node bin/secscan.js endpoints .
node bin/secscan.js sbom .
node bin/secscan.js compliance .
node bin/secscan.js dockerfile ./Dockerfile
node bin/secscan.js iam ./policy.json
node bin/secscan.js headers ./response.txt
node bin/secscan.js jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
node bin/secscan.js ssrf "http://169.254.169.254/"
```

`sca` reads `package.json` and `requirements.txt` and does not call OSV. `ssrf` classifies the URL and does not send a request. `sbom` builds CycloneDX and says the hashes are not file digests. `headers` reads a text file of `Name: value` lines. Nmap, DAST, IAST, EDR, SOC, and threat intel have no subcommand.

The table prints a summary. `--format json` writes the whole object. The exit code stays 0 when the read finishes.

To fail the command when the score goes past 50:

```bash
node bin/secscan.js . --max-risk 50
```

To fail when a critical finding exists:

```bash
node bin/secscan.js . --fail-on critical
```

To write SARIF 2.1.0:

```bash
node bin/secscan.js . --format sarif --output secscan-results.sarif
```

`--ignore` takes comma-separated globs. `--rules file.json` adds extra rules on top of the defaults. `--help` prints the full list.

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
