# GitLab Public Repository Risk Scanner

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1.1-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(20%2F20)-success.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)]()

An automated security scanning tool designed for DevSecOps workflows that inspects public (and authenticated private) GitLab repositories for a specified user or group, detects potential security risks, exposed credentials, and misconfigurations, and delivers actionable reports in CLI table, interactive Web Dashboard, JSON, and PDF formats.

---

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Features & Problem Statement Mapping](#features--problem-statement-mapping)
3. [Detection Categories & Rules](#detection-categories--rules)
4. [Getting Started](#getting-started)
5. [CLI Mode & Sample Output](#cli-mode--sample-output)
6. [Interactive Web Dashboard](#interactive-web-dashboard)
7. [REST API Endpoints](#rest-api-endpoints)
8. [Configuration & Private Repositories](#configuration--private-repositories)
9. [Docker Deployment](#docker-deployment)
10. [GitLab CI Pipeline](#gitlab-ci-pipeline)
11. [Running Tests](#running-tests)

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                                 USER INTERFACES                                   |
|   +--------------------------+  +-------------------------+  +----------------+   |
|   |  CLI Mode / ASCII Table  |  | Web Dashboard (HTML/JS) |  | REST API       |   |
|   +--------------------------+  +-------------------------+  +----------------+   |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                             CORE SCANNER ENGINE                                   |
|   +---------------------------------------------------------------------------+   |
|   | ScanService: Coordinates project discovery and executes detectors        |   |
|   +---------------------------------------------------------------------------+   |
|         |                                 |                                 |     |
|         v                                 v                                 v     |
|   +--------------------+        +--------------------+        +---------------+   |
|   | SensitiveFile      |        | ExposedSecret      |        | MissingMeta   |   |
|   | Detector           |        | Detector (Regex)   |        | Detector      |   |
|   +--------------------+        +--------------------+        +---------------+   |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                             GITLAB CLIENT SERVICE                                 |
|   - User / Group Project Discovery (Public & Private via Token)                   |
|   - Repository Tree Listing (Recursive file tree traversal)                       |
|   - Raw File Content Retrieval & Caching for text/code files                      |
+-----------------------------------------------------------------------------------+
```

---

## Features & Problem Statement Mapping

| Requirement | Implementation Status | Description |
| :--- | :---: | :--- |
| **Input Support** | Complete | Accepts GitLab username, group name, or project path with automatic account type resolution. |
| **GitLab API Integration** | Complete | Discovers projects, retrieves recursive repository trees, and fetches raw file contents. |
| **Category 1: Sensitive Files** | Complete | Detects `.env`, `.pem`, `id_rsa`, `config.json`, `secrets.yml`, `.key`, keystores, etc. (Severity: **High**). |
| **Category 2: Exposed Secrets** | Complete | Regex-based detection for AWS keys, GitLab/GitHub tokens, Slack tokens, private keys, passwords, database URIs with safe secret masking (Severity: **High** / **Medium**). |
| **Category 3: Missing Metadata** | Complete | Checks for missing `README.md` and missing `LICENSE` files (Severity: **Low**). |
| **CLI Table Output** | Complete | Formatted ASCII table with `Project Name \| Issue \| Severity` matching the exact assignment specification. |
| **Web Dashboard** | Complete | Responsive single-page UI at `http://localhost:8080/` with interactive metrics, search, and filtering. |
| **Export to JSON & PDF** | Complete | Built-in JSON export and native PDF document generation (`/api/v1/scan/export/pdf` and `/api/v1/scan/export/json`). |
| **Private Repo Authentication** | Complete | Pass GitLab Personal Access Token via header, config, query param, or web UI. |
| **OpenAPI Documentation** | Complete | OpenAPI 3.0 specification available at `/openapi.yaml` and interactive UI at `/swagger.html`. |
| **Unit Tests** | Complete | 20 unit tests covering all detectors, controllers, and services with 100% pass rate. |
| **Dockerization** | Complete | Multi-stage `Dockerfile` and `docker-compose.yml` for instant deployment. |
| **GitLab CI Pipeline** | Complete | Comprehensive `.gitlab-ci.yml` with test, build, docker, and automated scanning stages. |

---

## Detection Categories & Rules

### 1. Sensitive Files (Severity: HIGH)
Detects accidental commits of sensitive configuration files, keys, and credentials:
- Environment configs: `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`
- SSH / Asymmetric Private Keys: `id_rsa`, `id_dsa`, `id_ed25519`, `id_ecdsa`, `*.pem`, `*.key`
- Keystores / Certificates: `*.p12`, `*.pfx`, `*.pkcs12`, `*.keystore`, `*.jks`
- Secrets / Credential files: `secrets.yml`, `secrets.yaml`, `config.json`, `credentials.json`, `service-account.json`, `.htpasswd`, `docker-compose.override.yml`

### 2. Exposed Credentials & Secrets (Severity: HIGH / MEDIUM)
High-precision regex scanning across text and source code files:
- **AWS Access Key ID**: `\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b` (HIGH)
- **AWS Secret Access Key**: `(?i)aws.{0,20}?(?:secret|key|access)...` (HIGH)
- **GitLab Personal Access Token**: `\b(glpat-[0-9a-zA-Z_\-]{20,})\b` (HIGH)
- **GitHub Personal Access Token**: `\b((?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b` (HIGH)
- **Slack Token**: `\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b` (HIGH)
- **Private Key Headers**: `-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)? PRIVATE KEY-----` (HIGH)
- **Google Cloud API Key**: `\b(AIza[0-9A-Za-z_\-]{35})\b` (HIGH)
- **Stripe API Key**: `\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24})\b` (HIGH)
- **Database Connection URIs**: `postgres://`, `mysql://`, `mongodb://` with embedded passwords (HIGH)
- **Generic API Key / Secret**: `(?i)(?:api_key|secret_key|auth_token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]` (MEDIUM)
- **Hardcoded Passwords**: `(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]` (MEDIUM)

> [!NOTE]
> All detected secrets are masked in reports (e.g. `AKIA************1A2B`) to prevent accidental leaks while presenting actionable findings.

### 3. Missing Metadata (Severity: LOW)
Identifies repositories lacking essential documentation or governance:
- **Missing README**: No `README.md`, `README`, `README.txt`, or `README.rst` found in root directory.
- **Missing LICENSE**: No `LICENSE`, `LICENSE.md`, `LICENSE.txt`, or `COPYING` found in root directory.

---

## Getting Started

### Prerequisites
- Java 21 JDK
- Maven (or use included `./mvnw` wrapper)

### Build & Run
```bash
# Build the project
./mvnw clean package -DskipTests

# Run the web application
./mvnw spring-boot:run
```
The application will start on `http://localhost:8080`.

---

## CLI Mode & Sample Output

You can run automated scans directly from the terminal without starting a browser:

```bash
# Scan a user or group via CLI
./mvnw spring-boot:run -Dspring-boot.run.arguments="--scan.target=gitlab-org --scan.type=GROUP"

# Scan and export both JSON and PDF reports
./mvnw spring-boot:run -Dspring-boot.run.arguments="--scan.target=my-team --export.json=report.json --export.pdf=report.pdf"
```

### Example CLI Output (Matching Problem Statement)

```
==========================================================================================
 GitLab Repository Risk Scan Report - Target: demo-account (AUTO)
 Scanned At: 2026-09-07T12:00:00Z | Projects: 3 | Total Risks: 3 (High: 1, Med: 1, Low: 1)
==========================================================================================
+----------------+--------------------+------------+
| Project Name   | Issue              | Severity   |
+----------------+--------------------+------------+
| Project1       | Sensitive Files    | High       |
| Project2       | Exposed Secrets    | Medium     |
| Project3       | Missing Metadata   | Low        |
+----------------+--------------------+------------+

--- Detailed Findings ---
Project: Project1 (demo/project1)
  [HIGH] Sensitive file committed to repository (Exact sensitive filename match: .env)
    File: .env
    Remediation: Remove the file from Git history using 'git rm --cached .env', add to .gitignore, and revoke/rotate any contained credentials.

Project: Project2 (demo/project2)
  [MEDIUM] Detected Generic API Key in file: src/config.js at line 14
    File: src/config.js:14
    Snippet: const API_KEY = "api_sec_****************_prod";
    Remediation: Revoke and rotate this Generic API Key immediately. Never commit secrets into source control; use environment variables or a secrets manager.

Project: Project3 (demo/project3)
  [LOW] Missing README.md file in repository root
    File: README.md
    Remediation: Add a comprehensive README.md file describing project purpose, architecture, and setup instructions.
```

---

## Interactive Web Dashboard

Open `http://localhost:8080/` in your browser:

- **Target Input**: Enter GitLab username, group, or repository.
- **Scan Type Selector**: Auto-detect, User, Group, or Single Project.
- **Advanced Options Accordion**: Customize GitLab Base URL and supply Personal Access Token for private repository scanning.
- **Visual Metrics**: Repositories scanned, total risks, and High / Medium / Low severity counters.
- **Filterable Findings Table**: Filter by severity, category, or search keywords.
- **One-Click Exports**:
  - `Export JSON`: Downloads complete JSON report.
  - `Download PDF`: Downloads audit PDF report.
  - `Copy CLI Table`: Copies terminal ASCII table to clipboard.

---

## REST API Endpoints

| Method | Endpoint | Query / Body Parameters | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/scan` | JSON `ScanRequest` | Triggers a scan and returns `ScanResponse`. |
| `GET` | `/api/v1/scan` | `target`, `type`, `baseUrl`, `token`, `publicOnly` | Triggers a scan via query params. |
| `GET` | `/api/v1/scan/table` | `target`, `type` | Returns plain text CLI table. |
| `GET` | `/api/v1/scan/export/json` | `target`, `type` | Downloads JSON report attachment. |
| `GET` | `/api/v1/scan/export/pdf` | `target`, `type` | Downloads PDF report attachment. |
| `GET` | `/api/v1/gitlab/users/{username}/projects` | `username` | Lists public projects for a user. |
| `GET` | `/api/v1/gitlab/groups/{group}/projects` | `group` | Lists public projects for a group. |
| `GET` | `/health` | None | Returns system health status string. |

Interactive API documentation is available at `http://localhost:8080/swagger.html` and the raw OpenAPI 3.0 spec at `http://localhost:8080/openapi.yaml`.

---

## Configuration & Private Repositories

Configure defaults in `src/main/resources/application.yaml` or via environment variables:

```yaml
gitlab:
  base-url: ${GITLAB_BASE_URL:https://gitlab.com}
  api-path: ${GITLAB_API_PATH:/api/v4}
  # Keep this empty in source control; inject it through the environment when needed.
  token: ${GITLAB_TOKEN:}
  max-file-scan-size: ${GITLAB_MAX_FILE_SCAN_SIZE:524288} # 512 KB
  max-tree-items: ${GITLAB_MAX_TREE_ITEMS:500}
```

### Environment Variables
- `GITLAB_BASE_URL`: GitLab instance URL (e.g. `https://gitlab.com` or custom GitLab CE/EE instance)
- `GITLAB_TOKEN`: Personal Access Token with `read_api` / `read_repository` scopes.

---

## Docker Deployment

### Using Docker Compose
```bash
# Start container in background
docker compose up -d

# View logs
docker compose logs -f
```

### Using Docker CLI
```bash
# Build Docker image
docker build -t gitlab-risk-scanner .

# Run container
docker run -p 8080:8080 -e GITLAB_TOKEN="your-token" gitlab-risk-scanner
```

---

## GitLab CI Pipeline

The project includes `.gitlab-ci.yml` supporting:
1. `test`: Runs the unit test suite (`./mvnw test`).
2. `build`: Packages application artifact.
3. `docker-build`: Builds container image on `main` branch.
4. `automated-risk-scan`: Automatically triggers risk scans on target repositories via CI pipeline parameters (`SCAN_TARGET`).

---

## Running Tests

Execute the automated test suite with:

```bash
./mvnw test
```

All 20 unit tests verify:
- Sensitive file detection (`.env`, `id_rsa`, `.pem`, `config.json`, `secrets.yml`, `.key`)
- Exposed secrets regex scanning (AWS, GitLab, GitHub, Slack, Private Keys, Database URIs)
- Secret masking logic
- Missing metadata checks (README & LICENSE)
- CLI table generation and formatting
- Controller REST endpoints & error handling
