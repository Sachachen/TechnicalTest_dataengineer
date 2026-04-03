# CYNA — Technical Test (Data Engineer Internship)

## What I Built

This project is a real-time security data pipeline designed for a SOC use case. It ingests two data sources in parallel: security logs generated on the fly (IDS, web access, endpoint) and a threat intelligence feed from IPsum, which provides a list of malicious IPs with their confidence scores.

The core idea: enrich each security event with threat intel data, store everything reliably, and expose useful insights through a live-refreshing dashboard.

---

## Scope Coverage

All three requested deliverables are covered:

1. Ingestion of both data sources
2. Enrichment of security logs with threat intelligence
3. Visualization dashboard for SOC analysis

The entire solution runs on a single machine, with a lightweight footprint targeting 4 cores / 8 GB RAM.

---

## Global Architecture

The pipeline is structured as follows:

- `Security-Log-Generator/` — synthetic real-time log source
- `pipeline/fetch_ipsum.py` — fetches and refreshes the IPsum feed
- `pipeline/main.py` — tails logs, parses events, enriches with threat intel
- `pipeline/data/security.db` — SQLite database in WAL mode
- `dashboard/app.py` — Dash dashboard with 5-second auto-refresh

Data flow:

1. Download IPsum feed → load into `malicious_ips` table
2. Continuous security log generation
3. Near real-time log tailing
4. Event parsing and enrichment (`is_malicious_*`, `threat_score_*`)
5. Storage in `security_events`
6. Metrics visualization and recent malicious event display

---

## Repository Structure

```
TechnicalTest_dataengineer/
├── docker-compose.yml
├── README.md
├── start.sh
├── reset.sh
├── dashboard/
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
├── pipeline/
│   ├── db.py
│   ├── enricher.py
│   ├── fetch_ipsum.py
│   ├── main.py
│   ├── parsers.py
│   ├── tailer.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── data/
│       └── ipsum.txt
└── Security-Log-Generator/
```

---

## Architecture Decisions

This test was completed within one week. During the preparation phase, I identified solutions better suited for a production context: Kafka or Redpanda for ingestion, ClickHouse or PostgreSQL for storage, and Grafana for visualization. These tools would have made the pipeline more robust and scalable.

However, being familiar with a tool's purpose is not the same as being able to deploy and configure it reliably under time constraints. Rather than spending the week working with an unfamiliar stack and delivering something unstable, I chose to work with the technologies covered in my coursework — SQLite, Python, Dash — to deliver something functional, readable, and technically sound. The alternatives are documented here to demonstrate awareness of the broader ecosystem and a clear understanding of the trade-offs involved.

**Why SQLite instead of PostgreSQL or ClickHouse?**
SQLite is sufficient for a single-machine pipeline running on synthetic log volumes. It requires no infrastructure setup, and WAL mode enables concurrent reads without blocking writes. PostgreSQL would have been more appropriate at scale, but would have introduced infrastructure overhead (server management, connection pooling) that adds no value within this scope.

**Why no Kafka or message broker?**
A broker would cleanly decouple log generation from processing — which is the right architecture for production. However, deploying and configuring Kafka reliably requires significant hands-on experience. I chose to accept this coupling and document it transparently rather than deliver an unstable implementation.

**Why one thread per log type?**
Each log type (`ids`, `access`, `endpoint`) has its own format and generation rate. A dedicated thread per source isolates the parsers, allows independent failure handling, and makes it straightforward to add a new source without affecting the others.

**Why Dash for the dashboard?**
Dash is the data visualization library covered in my coursework. Grafana or Superset would be more appropriate for a real SOC environment, but would have required additional configuration and database integration that was not feasible within the available time.

**LRU cache on IP lookups and SQL indexes** are targeted performance optimizations to prevent dashboard slowdowns as log volume increases, without altering the core architecture.

In summary: the priority was to deliver something functional, maintainable, and honest about its limitations, rather than over-engineer with tools that could not be mastered within the given timeframe.

---

## What Works

- Real-time ingestion from the log generator
- Scheduled IPsum feed refresh
- Event enrichment on source and destination IPs
- Dashboard with 5-second auto-refresh and SOC-oriented views

Dashboard insights include:

- Total event volume and malicious hit count
- Unique malicious source IPs
- IDS event count
- Timeline of total vs malicious events
- Log type distribution
- Top malicious source and destination IPs
- IDS severity and alert type breakdowns
- HTTP status code distribution (access logs)
- Latest malicious events table

---

## Challenges and Trade-offs

**SQLite lock contention under concurrent writes** — Mitigated with `busy_timeout`, WAL mode, batched commits, and retries. This is not a definitive solution and remains a bottleneck under high write load.

**Startup race condition** — The `malicious_ips` table must be populated before the pipeline starts enriching events. Handled with a reload/retry mechanism on the IDS generator side.

**Dash callback desynchronization after reload** — When graph IDs change, the browser cache can cause mismatches. Resolved with a hard refresh or application restart.

**Intentionally simplified data model** — Readability and implementation speed were prioritized over full normalization. This is a deliberate trade-off for a test scope.

---

## Known Limitations

- SQLite is a single-node store with no distribution capability
- No message broker — ingestion and processing are tightly coupled
- No long-term retention or archival strategy
- Parsers assume the log generator formats remain stable

---

## Prerequisites and Environment Setup

**Docker** and **Docker Compose** must be installed before running the project.

---

### Installing Docker

#### Windows

1. Download **Docker Desktop** from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Run the installer and follow the setup steps
3. Docker Desktop may prompt you to enable **WSL 2** (Windows Subsystem for Linux) — accept and restart if required
4. Verify the installation by opening a terminal (PowerShell or CMD):

```bash
docker --version
docker compose version
```

#### macOS

1. Download **Docker Desktop** from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) (select Apple Silicon or Intel depending on your Mac)
2. Move Docker to the Applications folder
3. Launch Docker Desktop from Applications
4. Verify the installation in a terminal:

```bash
docker --version
docker compose version
```

#### Linux (Ubuntu / Debian)

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

### Clone the Repository

```bash
git clone <repo-url>
cd TechnicalTest_dataengineer-main
```

---

## Running the Project

### Option A — Docker (recommended)

From `TechnicalTest_dataengineer-main/`:

```bash
docker compose up --build
```

The dashboard is available at `http://localhost:8050`.

To stop:

```bash
docker compose down
```

Full reset (including volumes):

```bash
docker compose down -v
```

### Option B — Local Scripts

From `TechnicalTest_dataengineer-main/`:

```bash
./start.sh
```

This starts the IPsum fetcher scheduler, log generators, enrichment pipeline, and dashboard.

To stop and clean generated state:

```bash
./reset.sh
```

---

## Configuration

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

## Main Tables

| Table | Description |
|-------|-------------|
| `malicious_ips` | IPsum snapshot — IP address, confidence score, last update timestamp |
| `security_events` | Unified enriched event table (ids / access / endpoint) |

---

## What Could Be Improved Next

1. Migrate storage to **PostgreSQL** or **ClickHouse** for larger scale
2. Introduce a **message broker** (Kafka or equivalent) to decouple ingestion from processing
3. Add **observability instrumentation**: ingestion lag, events per second, callback latency
4. Implement **alerting rules** with notification channels
5. Expand **test coverage** for parser robustness and regression scenarios

---

The objective was to deliver a solution that is functional, reproducible, and transparent about its trade-offs — not to over-engineer for its own sake.
