# 🛡️ CYNA — Real-Time Security Data Pipeline (Data Engineer Internship)

## 📋 Project Description

A real-time security data pipeline designed for a SOC (Security Operations Center) use case. The project ingests two data sources in parallel — synthetic security logs (IDS, web access, endpoint) and a threat intelligence feed from IPsum — enriches each event with malicious IP data, stores everything in a local database, and exposes SOC-oriented insights through a live dashboard.

### Key Features

- 🔄 **Real-time ingestion** : Continuous tailing of IDS, access, and endpoint logs
- 🧠 **Threat enrichment** : Each event is enriched with IPsum threat intel (malicious flag + confidence score)
- 💾 **SQLite storage** : Lightweight local database in WAL mode for concurrent reads and writes
- 📊 **Live dashboard** : Dash-based dashboard with 5-second auto-refresh
- 🐳 **Containerized architecture** : Full Docker Compose deployment in one command
- ♻️ **Scheduled feed refresh** : IPsum feed automatically refreshed at configurable intervals

---

## 🏗️ Technical Architecture

### Technology Stack

| Component | Technology | Role |
|-----------|------------|------|
| **Log Generation** | Python (custom) | Synthetic real-time log source (IDS, access, endpoint) |
| **Threat Feed** | IPsum + Python | Malicious IP list with confidence scores |
| **Ingestion** | Python threads | One tailing thread per log type |
| **Enrichment** | Python + LRU cache | IP lookup and event enrichment |
| **Database** | SQLite (WAL mode) | Local storage with concurrent read support |
| **Dashboard** | Dash / Plotly | Interactive SOC visualization |
| **Containerization** | Docker Compose | Full orchestration in one command |

### Service Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Docker Compose                         │
├──────────────────┬───────────────────┬───────────────────────┤
│  Security Log    │   Ipsum Fetcher   │      Pipeline         │
│  Generator       │                   │                       │
├──────────────────┼───────────────────┼───────────────────────┤
│ - IDS logs       │ - Downloads IPsum │ - Tails log files     │
│ - Access logs    │ - Loads malicious │ - Parses events       │
│ - Endpoint logs  │   IPs into DB     │ - Enriches with       │
│ - config.yaml    │ - Scheduled       │   threat intel        │
│                  │   refresh         │ - Writes to SQLite    │
└──────────────────┴───────────────────┴───────────────────────┘
         │                  │                    │
         └──────────────────┼────────────────────┘
                            │
                    ┌───────────────┐
                    │   SQLite DB   │
                    │  (WAL mode)   │
                    └───────┬───────┘
                            │
                    ┌───────────────┐
                    │   Dashboard   │
                    │  (Dash/Plotly)│
                    │  :8050        │
                    └───────────────┘
```

### Data Flow

```
1. IPsum feed download  ──►  malicious_ips table
2. Log generator        ──►  ids / access / endpoint log files
3. Pipeline tailer      ──►  reads log files in near real-time
4. Enricher             ──►  adds is_malicious_*, threat_score_* fields
5. SQLite               ──►  stores enriched events in security_events
6. Dashboard            ──►  queries DB every 5s and renders SOC views
```

### Repository Structure

```
TechnicalTest_dataengineer-main/
├── docker-compose.yml              # Service orchestration
├── start.sh                        # Local launch script
├── reset.sh                        # Stop and clean generated state
│
├── pipeline/                       # Core ingestion and enrichment service
│   ├── main.py                     # Entry point — starts tailing threads
│   ├── tailer.py                   # Log file tailing logic
│   ├── parsers.py                  # Per-type event parsers
│   ├── enricher.py                 # Threat intel enrichment + LRU cache
│   ├── fetch_ipsum.py              # IPsum feed downloader and scheduler
│   ├── db.py                       # SQLite connection and schema
│   ├── Dockerfile
│   ├── requirements.txt
│   └── data/
│       └── ipsum.txt               # Local IPsum snapshot
│
├── dashboard/                      # Dash visualization service
│   ├── app.py                      # Dashboard layout and callbacks
│   ├── Dockerfile
│   └── requirements.txt
│
└── Security-Log-Generator/         # Synthetic log source
    ├── main.py                     # Generator entry point
    ├── config.yaml                 # Log type and volume configuration
    └── generators/                 # Per-type log generators
```

---

## 🎯 Architecture Decisions

This project was completed within one week. During the preparation phase, I identified solutions better suited for a production context: Kafka or Redpanda for ingestion, ClickHouse or PostgreSQL for storage, and Grafana for visualization. These tools would have made the pipeline more robust and scalable.

However, being familiar with a tool's purpose is not the same as being able to deploy and configure it reliably under time constraints. Rather than spending the week working with an unfamiliar stack and delivering something unstable, I chose to work with the technologies covered in my coursework. The alternatives are documented here to demonstrate awareness of the broader ecosystem and a clear understanding of the trade-offs involved.

### Technology Choices

**Why SQLite instead of PostgreSQL or ClickHouse?**

| | SQLite (chosen) | PostgreSQL / ClickHouse |
|--|--|--|
| Setup | Zero infrastructure | Requires server management |
| Concurrency | WAL mode handles concurrent reads | Better at scale |
| Fit for scope | Single machine, synthetic volume | Production / distributed use |

**Why no Kafka or message broker?**
A broker would cleanly decouple log generation from processing — the right architecture for production. Deploying and configuring Kafka reliably requires significant hands-on experience. Tight coupling is accepted here and documented transparently.

**Why one thread per log type?**
Each log type (`ids`, `access`, `endpoint`) has its own format and generation rate. A dedicated thread per source isolates parsers, allows independent failure handling, and makes it straightforward to add a new source.

**Why Dash for the dashboard?**
Dash is the data visualization library covered in my coursework. Grafana or Superset would be more appropriate for a real SOC environment but would have required additional configuration not feasible within the available time.

---

## 🚀 Prerequisites and Environment Setup

### Prerequisites

- **Docker** >= 20.10
- **Docker Compose** >= 2.0
- **Git**
- **Available ports** : 8050 (Dashboard)

---

### 1. Install Docker

#### 🪟 Windows

1. Download **Docker Desktop** from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Run the installer and follow the setup steps
3. Docker Desktop may prompt you to enable **WSL 2** (Windows Subsystem for Linux) — accept and restart if required
4. Make sure Docker Desktop is **running** (visible in the system tray) before using any `docker` command
5. Verify the installation in a terminal (PowerShell or CMD):

```bash
docker --version
docker compose version
```

#### 🍎 macOS

1. Download **Docker Desktop** from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)  
   *(select Apple Silicon or Intel depending on your Mac)*
2. Move Docker to the Applications folder and launch it
3. Wait for Docker Desktop to fully start (whale icon in the menu bar)
4. Verify in a terminal:

```bash
docker --version
docker compose version
```

#### 🐧 Linux (Ubuntu / Debian)

```bash
# Update package list
sudo apt update

# Install Docker
sudo apt install -y docker.io docker-compose-plugin

# Add your user to the docker group (avoids requiring sudo on every command)
sudo usermod -aG docker $USER

# Reload the session to apply the group change
newgrp docker

# Verify the installation
docker --version
docker compose version
```

---

### 2. Configuration de l'Environnement

```bash
# Créer un environnement virtuel Python
python -m venv venv

# Activer l'environnement (Windows)
venv\Scripts\activate

# Activer l'environnement (Linux/Mac)
source venv/bin/activate
```

---

### 3. Clone the Repository

```bash
git clone <repo-url>
cd TechnicalTest_dataengineer-main
```

---

## ▶️ Running the Project

### Option A — Docker (recommended)

```bash
# Build and start all services
docker compose up --build
```

The dashboard is available at **http://localhost:8050**

```bash
# Stop all services
docker compose down

# Full reset (removes containers, networks, and volumes)
docker compose down --rmi all --volumes --remove-orphans
```

> ⚠️ **Windows users** : Make sure Docker Desktop is fully started before running any `docker compose` command. If you see an error mentioning `dockerDesktopLinuxEngine`, Docker is not running yet.

### Option B — Local Scripts

```bash
# Start all services locally
./start.sh

# Stop and clean generated state
./reset.sh
```

---

## 🛠️ Useful Commands

### Container Management

```bash
# Start all services in the background
docker compose up -d --build

# View real-time logs for all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f pipeline
docker compose logs -f dashboard --tail 50

# Restart a specific service
docker compose restart pipeline
docker compose restart dashboard

# Rebuild without cache
docker compose build --no-cache
```

### Access Containers

```bash
# Shell into the pipeline container
docker compose exec pipeline /bin/bash

# Shell into the dashboard container
docker compose exec dashboard /bin/bash
```

### Check Container Status

```bash
docker compose ps
```

---

## 🔍 Troubleshooting

### Docker is not starting (Windows)

```
open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified
```

Docker Desktop is not running. Open it from the Start menu and wait for it to fully start before retrying.

### Container name conflict

```
Error: Conflict. The container name "/security-log-generator" is already in use
```

```bash
# Remove orphaned containers from the project only
docker compose down --remove-orphans

# Or force-remove the specific container
docker rm -f security-log-generator
```

### Full Docker reset (project only)

```bash
docker compose down --rmi all --volumes --remove-orphans
```

### Dashboard shows no data

The IPsum feed or pipeline may not have started yet. Check the logs:

```bash
docker compose logs ipsum-fetcher
docker compose logs pipeline
```

Wait a few seconds after startup — the `malicious_ips` table needs to be populated before enrichment begins.

### Port 8050 already in use

```bash
# Windows
netstat -ano | findstr :8050

# Linux / macOS
lsof -i :8050
```

Kill the process using the port, then restart with `docker compose up`.

---

## ⚙️ Configuration

### Log Generator

File: `Security-Log-Generator/config.yaml`

| Key | Description |
|-----|-------------|
| `log_type` | `ids`, `access`, `endpoint`, or `all` |
| `event_distribution` | `linear` or `wave` |
| `no_events`, `write_time` | Linear mode only |
| `frequency`, `amplitude`, `sample_rate`, `duration`, `stretch` | Wave mode only |

For high-volume testing, increase write parameters or run multiple generator processes in parallel.

### Threat Feed

File: `pipeline/fetch_ipsum.py`

| Option | Default | Description |
|--------|---------|-------------|
| `--min-score` | `3` | Minimum score to flag an IP as malicious |
| `--daemon` | — | Runs the fetcher as a background daemon |
| `--interval-hours` | `24` | Feed refresh interval |

---

## 📊 Dashboard Insights

| Metric | Description |
|--------|-------------|
| Total events | Overall ingested event count |
| Malicious hits | Events matched against threat intel |
| Unique malicious IPs | Distinct source IPs flagged as malicious |
| IDS event count | Volume of intrusion detection events |
| Timeline | Total vs malicious events over time |
| Log type distribution | Breakdown by ids / access / endpoint |
| Top malicious IPs | Most frequent malicious source and destination IPs |
| IDS severity breakdown | Alert severity distribution |
| HTTP status distribution | Response code breakdown from access logs |
| Latest malicious events | Real-time table of recent flagged events |

---

## 🗄️ Database Schema

### `malicious_ips`

| Column | Type | Description |
|--------|------|-------------|
| `ip` | TEXT | IP address |
| `score` | INTEGER | IPsum confidence score |
| `updated_at` | TIMESTAMP | Last feed update timestamp |

### `security_events`

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | TIMESTAMP | Event timestamp |
| `log_type` | TEXT | `ids`, `access`, or `endpoint` |
| `src_ip` | TEXT | Source IP address |
| `dst_ip` | TEXT | Destination IP address |
| `severity` | TEXT | Event severity (IDS only) |
| `is_malicious_src` | BOOLEAN | Source IP flagged by IPsum |
| `is_malicious_dst` | BOOLEAN | Destination IP flagged by IPsum |
| `threat_score_src` | INTEGER | Source IP confidence score |
| `threat_score_dst` | INTEGER | Destination IP confidence score |

---

## ⚠️ Known Limitations

- SQLite is a single-node store with no distribution capability
- No message broker — ingestion and processing are tightly coupled
- No long-term retention or archival strategy
- Parsers assume the log generator formats remain stable
- SQLite lock contention can occur under sustained high write load

---

## 🔮 What Could Be Improved Next

1. Migrate storage to **PostgreSQL** or **ClickHouse** for larger scale
2. Introduce a **message broker** (Kafka or equivalent) to decouple ingestion from processing
3. Add **observability instrumentation** : ingestion lag, events per second, callback latency
4. Implement **alerting rules** with notification channels
5. Expand **test coverage** for parser robustness and regression scenarios
6. Replace Dash with **Grafana** for a production-grade SOC dashboard

---

The objective was to deliver a solution that is functional, reproducible, and transparent about its trade-offs — not to over-engineer for its own sake.