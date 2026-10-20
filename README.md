# ThreatLens

**An independent threat intelligence API.** Submit an indicator of compromise (IOC), get back a consolidated verdict built from several public reputation sources, with every analysis stored for later review.

> **Status: under active development.** The core API, database, caching and Docker setup work today. Authentication, a web dashboard and integrations are planned (see [Roadmap](#roadmap)).

ThreatLens is deliberately vendor-neutral: it exposes a plain REST API, so a script, a SIEM/SOAR platform or any custom tool can call it the same way.

![ThreatLens API docs](docs/swagger.png)

![Analysis of a known malicious file hash](docs/swagger-response.png)

## Features

- Analyze four IOC types: **IP address, domain, URL and file hash**
- Query **VirusTotal** (all four types) and **AbuseIPDB** (IP addresses only)
- Compute a single **Threat Score** (0-100) with a `low` / `medium` / `high` level
- **Validate** that the IOC really matches its declared type before spending any API quota
- **Cache** results in PostgreSQL so repeated lookups do not consume quota
- Keep a **history** of every analysis
- Graceful handling of provider failures (timeouts, bad keys, rate limits)
- One-command start with **Docker Compose**

## Architecture

```
Client (script, SIEM/SOAR, curl, future dashboard)
        |  HTTP / JSON
        v
   FastAPI  (routing, validation)
        |
        +--> validators.py   check that ioc matches type
        +--> cache.py        reuse a recent result if one exists
        +--> virustotal.py   VirusTotal API
        +--> abuseipdb.py    AbuseIPDB API
        +--> scoring.py      combine provider results into a score
        |
        v
   PostgreSQL  (SQLAlchemy models, Alembic migrations)
```

**Stack:** Python, FastAPI, Uvicorn, Pydantic, SQLAlchemy, Alembic, PostgreSQL, Docker.

## Quick start (Docker)

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine with the Compose plugin) and two free API keys:

- VirusTotal: <https://www.virustotal.com/gui/join-us>
- AbuseIPDB: <https://www.abuseipdb.com/register>

```bash
git clone https://github.com/z-lansari/threat-lens.git
cd threat-lens

# create your configuration file, then put your API keys in it
cp .env.example .env          # Windows (PowerShell/CMD): copy .env.example .env

docker compose up -d --build
```

Open <http://localhost:8000/docs> for the interactive API documentation.

Useful commands:

```bash
docker compose logs api       # see what the API is doing
docker compose down           # stop (your data is kept in a volume)
docker compose down -v        # stop AND delete the database volume
```

The first start creates an empty PostgreSQL database and applies the Alembic migrations automatically.

## Running without Docker

You need Python 3.14 and a running PostgreSQL server with an empty database.

```bash
python -m venv venv
source venv/bin/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

cp .env.example .env          # then edit DATABASE_URL and the API keys
alembic upgrade head
python -m uvicorn main:app --reload
```

## Configuration

All settings live in `.env` (never commit this file; it is already in `.gitignore`).

| Variable | Purpose | Default |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | none, required |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | none, required for IP lookups |
| `DATABASE_URL` | PostgreSQL connection string (used when running without Docker) | none |
| `CACHE_TTL_HOURS` | How long a stored result can be reused | `24` |

With Docker Compose, `DATABASE_URL` is set automatically to point at the bundled database container, so the value in `.env` is ignored there.

## API

### `POST /analyze`

```json
{
  "ioc": "8.8.8.8",
  "type": "ip",
  "force_refresh": false
}
```

- `type` is one of `ip`, `domain`, `url`, `hash`
- `force_refresh` is optional (default `false`); set it to `true` to skip the cache and query the providers again

Abridged response:

```json
{
  "id": 1,
  "ioc": "8.8.8.8",
  "type": "ip",
  "created_at": "2026-10-19T18:13:32+00:00",
  "virustotal": { "malicious": 0, "suspicious": 0, "undetected": 36, "harmless": 56, "timeout": 0 },
  "abuseipdb": { "abuseConfidenceScore": 0, "countryCode": "US", "isp": "Google LLC" },
  "threat": { "threat_score": 0, "level": "low" },
  "cached": false
}
```

`cached` tells you whether the result came from the database (`true`) or from a fresh provider query (`false`).

An IOC that does not match its type is rejected with `422` before anything is stored or sent to a provider:

```json
{ "detail": "'www.google.com' is not a valid ip" }
```

### `GET /history`

Returns every stored analysis.

### `GET /health`

Returns `{"status": "ok"}`.

### Provider coverage

| IOC type | VirusTotal | AbuseIPDB |
|---|---|---|
| ip | yes | yes |
| domain | yes | no |
| url | yes | no |
| hash | yes | no |

AbuseIPDB only covers IP addresses, so its result is `null` for the other types.

## How the Threat Score works

This is a simple first version, not a scientific model.

1. **VirusTotal:** the share of engines flagging the IOC, `(malicious + suspicious) / (malicious + suspicious + harmless + undetected) * 100`
2. **AbuseIPDB:** its own `abuseConfidenceScore` (0-100)
3. The final score is the **highest** of the available scores, so one source reporting a threat is enough to raise the alarm
4. Level: `0-24` low, `25-59` medium, `60-100` high

If a provider fails or returns nothing, it is ignored. If every provider fails, `threat_score` and `level` are `null`. The thresholds are arbitrary starting points and are easy to adjust in `scoring.py`.

## How validation and caching work

**Validation** (`validators.py`): IPs are checked with Python's `ipaddress` module, hashes must be 32, 40 or 64 hexadecimal characters (MD5, SHA-1, SHA-256), URLs must start with `http://` or `https://`, and domains must contain at least one dot.

**Caching** (`cache.py`): before calling the providers, ThreatLens looks for a stored result for the same IOC and type that is newer than `CACHE_TTL_HOURS`. Rows with no result, or with a provider error, are never reused. Older rows are never deleted, so `/history` keeps the full record.

## Free-tier limits

The free VirusTotal plan allows about 4 requests per minute and 500 per day. The cache exists largely to stay within those limits.

## Troubleshooting

- **Port 8000 already in use:** change the first number in the `ports` entry of `docker-compose.yml`, for example `"8001:8000"`, then open <http://localhost:8001/docs>.
- **`.env` not found:** run `cp .env.example .env` (or `copy` on Windows) before `docker compose up`.
- **Build fails with `additional privileges requested: pass "--allow=fs.read=Dockerfile"`:** seen on one Windows setup where the project folder was reached through a symlink. Cloning to a plain folder avoided it. Setting `BUILDX_BAKE_ENTITLEMENTS_FS=0` in the current shell also worked.
- **Provider returns `error` with status 401:** the API key in `.env` is wrong. Restart the API after fixing it.

## Security notes

- ThreatLens has **no authentication yet**. Do not expose it to the internet as it is.
- The PostgreSQL password in `docker-compose.yml` is `postgres`, which is fine for local use only. Use a strong secret for any real deployment.

## Roadmap

- [x] REST API with input validation
- [x] PostgreSQL storage and Alembic migrations
- [x] VirusTotal and AbuseIPDB integration
- [x] Threat Score
- [x] Result caching
- [x] Docker Compose setup
- [ ] Authentication (JWT for users, API keys for external systems)
- [ ] Web dashboard
- [ ] Integration examples (Wazuh, Shuffle, Splunk and others)
- [ ] Automated tests
- [ ] More providers (AlienVault OTX, GreyNoise, URLhaus)
- [ ] Contribution guide, changelog and tagged releases

## License

MIT, see [LICENSE](LICENSE).
