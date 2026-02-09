# PetPulse Server (Backend)

The **PetPulse Server** is the core backend monorepo for the PetPulse platform. Built with **Rust**, it orchestrates the API, background processing, and internal agent services. It leverages a modern, high-performance stack to ensure reliability and scalability for pet monitoring.

## 🏗️ Architecture & Services

![Architecture Diagram](./ArchitectureDiagram.png)

The repository is structured as a Cargo workspace containing three primary binaries:

| Service | Binary | Description | Key Tech |
| :--- | :--- | :--- | :--- |
| **API Server** | `server` | The main REST API entry point. Handles client requests, authentication, and database interactions. | `Axum`, `SeaORM`, `JWT` |
| **Worker** | `worker` | Background processor for heavy lifting. Handles video analysis (Gemini API) and email notifications (SendGrid). | `Redis` (Queue), `Gemini`, `SendGrid` |
| **Agent** | `agent` | Internal service for specific node-level tasks or lightweight monitoring. | `Tokio` |

## 🛠️ Technology Stack

- **Language**: Rust (Edition 2021)
- **Web Framework**: [Axum](https://github.com/tokio-rs/axum)
- **Database**: PostgreSQL (via [SeaORM](https://www.sea-ql.org/SeaORM/))
- **Queue**: Redis (for background jobs)
- **Cloud Services**:
  - **Google Cloud Storage (GCS)**: Video storage.
  - **Google Cloud Pub/Sub**: Event messaging.
  - **Google Gemini API**: AI-powered video analysis.
- **Observability**: OpenTelemetry (OTEL), Prometheus, Jaeger/Tempo.

## 🚀 Getting Started

### Prerequisites
- **Docker** & **Docker Compose** installed.
- **Environment Variables**: Create a `.env` file (see [Configuration](#-configuration)).

### Run with Docker Compose
To start the entire stack (Postgres, Redis, Server, Worker) with a single command:

```bash
docker-compose up --build
```

The API will be available at `http://localhost:8080`.

## ⚙️ Configuration

The application is configured via environment variables. Create a `.env` file with the following keys:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL Connection String | `postgres://user:pass@localhost:5432/petpulse` |
| `REDIS_URL` | Redis Connection String | `redis://localhost:6379` |
| `GCS_BUCKET_NAME` | Google Cloud Storage Bucket | `petpulse-videos-dev` |
| `GEMINI_API_KEY` | Google Gemini AI API Key | `AIzaSy...` |
| `SENDGRID_API_KEY` | SendGrid API Key for Emails | `SG....` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP Service Account JSON | `./gcp-key.json` |
| `RUST_LOG` | Log level (tracing) | `debug,hyper=info` |

## 🚨 Escalation Workflow

The following diagram illustrates the complete journey of an alert, from video upload to user notification:

![Escalation Workflow](./Workflow.png)

### 🧠 Understanding Alerts & Interventions

The system classifies behavior into different severity levels, triggering appropriate autonomous responses:

| Severity | Description | Intervention Action |
| :--- | :--- | :--- |
| **Low** |  Minor behavioral changes (e.g., slight increase in sleeping). | **Agent Intervention**: Event logged for analysis. |
| **Medium** | Noticeable deviation from baseline (e.g., missed meal, pacing). | **Agent Intervention**: Gentle app nudge to owner. |
| **High** |  Significant issue detected (e.g., vomiting, extreme lethargy). | **Alert**: Immediate Push Notification & Email. |
| **Critical** | Emergency situation (e.g., seizure, collapse). | **Emergency Protocol**: SMS to Owner & Emergency Contacts + "Quick Actions". |

#### 🔑 Key Activities Monitored
The AI analyzes video for specific activities including:
*   **Eating/Drinking**: Monitoring appetite and hydration.
*   **Sleeping/Resting**: Tracking rest patterns.
*   **Physical Activity**: Walking, running, playing.
*   **Unusual Behaviors**: Vomiting, limping, scratching, pacing.