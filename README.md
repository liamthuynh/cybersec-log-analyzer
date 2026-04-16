# CyberScope

**SOC-grade log analysis in your browser.**

CyberScope lets security analysts upload proxy or web server logs, automatically detect anomalies, and get an AI-generated threat briefing — all without leaving a web UI.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

| | |
|---|---|
| **Upload** | Drag-and-drop `.txt`, `.log`, or `.csv` log files (up to 16 MB) |
| **Parse** | Auto-detects ZScaler-style proxy logs, Apache/Nginx combined logs, and generic CSV |
| **Detect** | Eight rule-based anomaly detectors with confidence scores and human-readable explanations |
| **Summarize** | Optional Claude AI layer produces an executive summary, threat level, key findings, and a SOC-style event timeline |
| **Review** | Browse results in a filterable anomaly table, an hourly activity chart, and a full AI analysis panel |
| **History** | All uploads are persisted per user; click any past upload to reload its full results |

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Local](#quick-start--local)
- [Log Format](#log-format)
- [Anomaly Detection](#anomaly-detection)
- [AI Analysis](#ai-analysis)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)

---

## Features

**Detection**
- High request rate from a single IP (>20 req / 60 s window)
- Off-hours access (before 06:00 or after 22:00 UTC)
- Large data transfers (>5× the session median)
- Blocked or denied traffic
- Error-rate spikes per source IP
- Suspicious domains — risky TLDs, known bad keywords, high-risk categories
- Credential-stuffing patterns (≥5 failed POST logins in 120 s)
- Slow requests that may indicate tunneling or covert exfiltration

**Dashboard**
- Summary metrics: entries, anomalies, unique IPs, data volume, users, blocked count
- Hourly timeline chart with total requests, errors, and blocked traffic
- Top domains and source IPs breakdown
- Anomaly table filterable by severity (critical / high / medium / low) with expandable detail rows
- Confidence-score bar on each anomaly
- AI analysis panel with threat level badge, key findings cards, and recommended actions

**Platform**
- JWT-based auth with user registration and a built-in demo account
- PostgreSQL-backed upload history with per-user isolation
- Docker Compose for a one-command local stack
- Next.js API rewrites — frontend and backend on the same origin in every environment

---

## Architecture

```
Browser
  └── Next.js 14 (TypeScript + Tailwind + Recharts)
        └── /api/* rewrite proxy
              └── Flask REST API (Python 3.11)
                    ├── parser.py      — log format detection & normalization
                    ├── analyzer.py    — rule-based anomaly detection
                    ├── ai_analyzer.py — Claude API integration
                    └── PostgreSQL 16  — users & upload persistence
```

---

## Quick Start — Docker

The fastest path. Requires Docker Desktop.

**1. Clone and configure**

```bash
git clone https://github.com/your-username/cybersec-log-analyzer.git
cd cybersec-log-analyzer
cp .env.example .env
```

Open `.env` and set the two values below. Everything else has working defaults.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Signs JWT tokens. Generate one: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ANTHROPIC_API_KEY` | No | Enables AI analysis. Get one at [console.anthropic.com](https://console.anthropic.com) |

**2. Start the stack**

```bash
docker compose up --build
```

Three services start in dependency order: `postgres` → `backend` → `frontend`.

**3. Open the app**

- UI: `http://localhost:3000`
- API: `http://localhost:8000`

**Demo credentials:** `demo` / `demo1234`

**4. Upload a sample log**

The repository ships with a realistic test log:

```
sample_logs/sample_proxy_log.txt
```

Drag it into the upload zone to see anomaly detection and (if you set an API key) the AI analysis panel.

---

## Quick Start — Local

Requires Python 3.11+, Node.js 20+, and PostgreSQL 15+.

**1. Create a database**

```bash
createdb cyberscope
```

**2. Configure the backend**

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export FLASK_ENV=development
export DATABASE_URL=postgresql://localhost/cyberscope
export CORS_ORIGINS=http://localhost:3000
# Optional:
export ANTHROPIC_API_KEY=sk-ant-...
```

**3. Start the backend**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

**4. Start the frontend**

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

**Smoke test**

Once the stack is running, validate the main flow end-to-end:

```bash
./scripts/smoke_test.sh
```

---

## Log Format

CyberScope auto-detects the format from the first content line. Three formats are supported out of the box:

### ZScaler-style proxy log (primary)

Pipe-delimited fields, no header required:

```
timestamp | source_ip | user | method | url | status_code | bytes_sent | bytes_received | action | category | user_agent | duration_ms
```

Example:

```
2024-01-15T08:23:41Z | 10.0.1.100 | jsmith | GET | https://example.com/api/data | 200 | 1024 | 8192 | ALLOW | Business | Mozilla/5.0 | 234
```

### Apache / Nginx combined log

Standard combined log format is detected automatically.

### Generic CSV

Any CSV file with a header row is parsed; fields are mapped by column name where possible.

> The proxy format is recommended for this project. It contains the fields a SOC analyst cares about most — user, source IP, destination, action, category, volume, and timing — and maps directly to all eight detection rules.

---

## Anomaly Detection

Implemented in [`backend/analyzer.py`](backend/analyzer.py).

Each anomaly includes:

| Field | Description |
|---|---|
| `rule` | Machine-readable rule identifier |
| `reason` | Human-readable explanation of why the entry was flagged |
| `confidence` | `0.0` – `1.0` score based on deviation from baseline |
| `severity` | `critical` / `high` / `medium` / `low` |
| `entry` | The raw log fields for the flagged line |

Rules apply to the full upload in a single pass and are deduplicated by line number — a line that triggers multiple rules produces one merged anomaly.

---

## AI Analysis

Implemented in [`backend/ai_analyzer.py`](backend/ai_analyzer.py).

When `ANTHROPIC_API_KEY` is set and the AI toggle is on, the backend:

1. Builds a context packet — summary statistics, top anomalies, and a representative sample of up to 50 log entries (anomalous entries prioritized, remaining slots filled evenly across the file)
2. Sends the packet to **Claude** (`claude-sonnet-4-6`) via the Anthropic API
3. Returns structured JSON with the fields below

| Field | Description |
|---|---|
| `executive_summary` | One-paragraph threat overview |
| `threat_level` | `critical` / `high` / `medium` / `low` / `minimal` |
| `key_findings` | Array of titled findings with severity, affected entities, and a recommendation |
| `timeline` | Chronological event sequence with significance ratings |
| `patterns_detected` | Short list of behavioral patterns identified |
| `recommended_actions` | Prioritized response actions for the analyst |

If no API key is configured, the backend returns a rule-based fallback summary so the panel is never blank.

---

## API Reference

### Public

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create a new account |
| `POST` | `/api/auth/login` | Authenticate and receive a JWT |
| `GET` | `/api/health` | Health check |

### Authenticated (Bearer token required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload a log file for analysis |
| `GET` | `/api/uploads` | List all uploads for the current user |
| `GET` | `/api/uploads/<id>` | Get full results for a specific upload |

---

## Project Structure

```
cybersec-log-analyzer/
├── backend/
│   ├── app.py             # Flask app, routes, auth, DB
│   ├── parser.py          # Log format detection and normalization
│   ├── analyzer.py        # Rule-based anomaly detection engine
│   ├── ai_analyzer.py     # Claude API integration
│   ├── config.py          # Environment-based configuration
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── dashboard/ # Main analysis UI
│   │   │   ├── login/     # Auth page
│   │   │   └── globals.css
│   │   ├── components/
│   │   │   ├── AnomalyTable.tsx
│   │   │   ├── AISummaryPanel.tsx
│   │   │   ├── StatsCards.tsx
│   │   │   ├── TimelineChart.tsx
│   │   │   └── UploadHistory.tsx
│   │   └── lib/
│   │       └── api.ts     # Typed API client
│   ├── Dockerfile
│   ├── next.config.js
│   └── package.json
├── sample_logs/
│   └── sample_proxy_log.txt
├── scripts/
│   └── smoke_test.sh
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## License

MIT
