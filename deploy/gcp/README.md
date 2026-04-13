# QuantumShield on Google Cloud

This folder documents a **hybrid** deployment: API and databases in GCP, static web build pointing at the cloud API, Electron with optional runtime config. **Do not commit secrets**; use Secret Manager and `.env` only on machines that run the stack.

## 1. Runtime decisions (defaults)

| Choice | Recommendation | Rationale |
|--------|----------------|-----------|
| **API compute** | **Compute Engine (GCE)** with Docker | Long-running scans, many subprocesses (nmap, subfinder, TLS tools). Easier outbound to **Tailscale** / private LM Studio (Option A). |
| **Alternative** | **Cloud Run** | Good for short requests; raise timeout / use Jobs for long scans; add **VPC connector** for private Cloud SQL. |
| **PostgreSQL** | **Cloud SQL for PostgreSQL** | Managed backups, same region as GCE (`us-central1` is a sensible default). |
| **MongoDB** | **MongoDB Atlas on GCP** | Same region as Cloud SQL/GCE; set `MONGO_URI` from Atlas. |
| **LLM Option A** | LM Studio on Windows + **Tailscale** (or Cloudflare Tunnel) on GCE + PC | Set `LLM_BASE_URL` to the Tailscale IP/hostname of the PC. Use `LLM_API_KEY` if the tunnel enforces a token. |
| **LLM Option B** | **Vertex AI** (Gemma) or other managed endpoint | No home dependency; point `LLM_BASE_URL` at the OpenAI-compatible URL and adjust auth in `lm_studio_client.py` if headers differ. |
| **Frontend** | **Firebase Hosting** or **GCS + HTTPS load balancer** | Upload `Frontend/dist` after `npm run build` with production `VITE_API_BASE_URL`. |
| **HTTPS** | Google-managed certificate on **HTTPS LB** in front of GCE instance group, or **Caddy/nginx** on the VM with a public DNS name. |

These defaults satisfy the plan’s “choose runtime” step; change only if you need Cloud Run-only or fully managed LLM.

## 2. Billing guardrails ($300 credits)

1. In Google Cloud Console: **Billing → Budgets & alerts** → create a budget (e.g. $50 and $100) with email alerts.
2. Use **e2** machine types; use the **smallest Cloud SQL** tier for dev.
3. **Stop the GCE VM** when idle: Console → Compute Engine → VM → **Stop** (you are not charged for stopped CPU; disk and static IP may still incur cost). **Start** again before demos.
4. Set **quotas** on expensive SKUs (GPU, large SQL) if you are worried about overspend.

## 3. Provision data (Cloud SQL + Atlas)

Run in one region (e.g. `us-central1`).

### Cloud SQL (PostgreSQL)

```bash
gcloud config set project YOUR_PROJECT_ID

gcloud sql instances create quantumshield-pg \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1 \
  --root-password=GENERATE_STRONG_PASSWORD

gcloud sql databases create quantumshield --instance=quantumshield-pg

gcloud sql users create qs_app \
  --instance=quantumshield-pg \
  --password=GENERATE_APP_PASSWORD
```

Build `POSTGRES_URL` for the app (asyncpg):

`postgresql+asyncpg://qs_app:APP_PASSWORD@/quantumshield?host=/cloudsql/PROJECT:REGION:quantumshield-pg`

On GCE with Cloud SQL Auth Proxy as a sidecar, or use the **Unix socket** path documented in [Cloud SQL Python connector](https://cloud.google.com/sql/docs/postgres/connect-auth-proxy). For a VM with **public IP** authorized on the instance, use:

`postgresql+asyncpg://qs_app:PASSWORD@CLOUD_SQL_PUBLIC_IP:5432/quantumshield`

### MongoDB Atlas

1. Create a **GCP** cluster in the same region.
2. Database user + password; network access: GCE VM egress IP (or `0.0.0.0/0` only for quick tests — not recommended for production).
3. Copy the **SRV connection string** into `MONGO_URI` (see `deploy/gcp/env.cloud.example`).

## 4. Build and run the API (Docker on GCE)

From repo root (with Docker):

```bash
docker build -t quantumshield-api:latest -f Backend/Dockerfile Backend
```

Tag and push to **Artifact Registry**:

```bash
gcloud artifacts repositories create quantumshield --repository-format=docker --location=us-central1 --description="QuantumShield API"
gcloud auth configure-docker us-central1-docker.pkg.dev

docker tag quantumshield-api:latest us-central1-docker.pkg.dev/YOUR_PROJECT_ID/quantumshield/api:latest
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/quantumshield/api:latest
```

On the VM (after installing Docker), run (adjust env file path):

```bash
docker run -d --name quantumshield-api --restart unless-stopped -p 8000:8000 \
  --env-file /opt/quantumshield/.env \
  us-central1-docker.pkg.dev/YOUR_PROJECT_ID/quantumshield/api:latest
```

**Firewall**: allow **tcp:443** (and **tcp:8000** only if no reverse proxy) from the load balancer health check ranges or your IP for testing.

**CORS**: set `CORS_ORIGINS` to your real static origins (comma-separated), e.g. `https://your-app.web.app,https://your-domain.com`. Avoid `*` in production if you use cookies.

**Secrets**: prefer **Secret Manager** + startup script that exports env or mounts files — do not bake `.env` into the image.

### Optional: Cloud Run

For Cloud Run, use a **VPC connector** if Cloud SQL uses private IP. Increase **request timeout** for scans or use **Cloud Run jobs** for batch/long work. Example build/deploy:

```bash
gcloud builds submit --tag us-central1-docker.pkg.dev/YOUR_PROJECT_ID/quantumshield/api:latest Backend
gcloud run deploy quantumshield-api \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT_ID/quantumshield/api:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "..." \
  --timeout=900 \
  --memory=4Gi \
  --cpu=2
```

(Exact flags depend on Cloud SQL connector sidecar vs proxy — see Google’s “Connect Cloud Run to Cloud SQL” guide.)

## 5. Frontend static hosting

1. Copy `Frontend/.env.example` to `Frontend/.env.production.local` (gitignored) and set:

   `VITE_API_BASE_URL=https://YOUR_API_HOST/api/v1`

2. Build:

   ```bash
   cd Frontend && npm ci && npm run build
   ```

3. **Firebase Hosting** (example):

   ```bash
   npm install -g firebase-tools
   firebase login
   firebase init hosting
   firebase deploy --only hosting
   ```

   Copy `deploy/gcp/firebase.json.example` to `Frontend/firebase.json` and set `public` to `dist` (or deploy `dist` contents per your project layout).

WebSockets use **`wss://`** when `VITE_API_BASE_URL` is `https://` (see `useWebSocket.ts` + `runtimeConfig.ts`).

### Vercel (frontend only)

Vercel hosts the **React build**. The **FastAPI backend stays on GCP** (GCE or Cloud Run). Users’ browsers call your **HTTPS API URL**; they never talk to LM Studio directly.

1. Put the API on the public internet with **HTTPS** (Google HTTPS load balancer, **Cloud Run** managed TLS, or **Caddy** on the VM). Note the origin, e.g. `https://api.yourdomain.com`.
2. In [Vercel](https://vercel.com): **Add New… → Project** → import your Git repo.
3. **Root Directory**: set to `Frontend` (the Vite app lives there, not the repo root).
4. **Framework Preset**: Vite (auto-detected is fine).
5. **Environment Variables** (Production — and Preview if you want preview deploys to hit a staging API):

   | Name | Example value |
   |------|----------------|
   | `VITE_API_BASE_URL` | `https://api.yourdomain.com/api/v1` |

6. Deploy. After the first deploy, open the Vercel URL; the UI should show API health if CORS is correct.

**Backend CORS** on GCP must allow your Vercel origin (comma-separated, no spaces):

```env
CORS_ORIGINS=https://your-app.vercel.app,https://api.yourdomain.com
```

Use your real production hostname(s). Wildcard `*` works for quick tests but is looser than listing `https://….vercel.app`.

### LM Studio (Gemma) on Windows while the API is on GCP

Only the **GCP server** needs to reach LM Studio — not Vercel and not visitors’ browsers. Your home router blocks inbound connections from GCP, so use a **private path** from the VM to your PC.

**Recommended: Tailscale (same “tailnet” on VM + Windows)**

1. Sign up at [tailscale.com](https://tailscale.com) and install Tailscale on **Windows** (where LM Studio runs) and on the **GCE VM** (Linux: follow [Tailscale on Linux](https://tailscale.com/kb/1017/install)).
2. Approve both machines in the Tailscale admin console.
3. On Windows, open the Tailscale app and note the **Tailscale IP** (usually `100.x.x.x`).
4. In **LM Studio**: load Gemma → **Local Server** → start the server; confirm the port (often **1234**). If Copilot fails from GCP, set the server to accept connections from the LAN/tailnet (avoid binding only to `127.0.0.1` if that option exists).
5. On the GCP VM, in `/opt/quantumshield/.env` (or Secret Manager → env), set:

   ```env
   LLM_BASE_URL=http://100.x.x.x:1234/v1/chat/completions
   LLM_MODEL=gemma-3-4b-it
   LLM_TIMEOUT_SECONDS=120
   LLM_TRUST_ENV=false
   ```

   Use your **actual** Windows Tailscale IP and the **exact** model id shown in LM Studio. Path must end with `/v1/chat/completions` unless you already use a full URL (the backend normalizes it).

6. **Restart the API container** after changing env. From the VM, test:

   ```bash
   curl -sS -m 10 http://100.x.x.x:1234/v1/models
   ```

   If that works from the VM, Copilot from the Vercel site should work once users are logged in and the scan API is healthy.

7. **Reality check**: Windows must stay **on**, Tailscale connected, and LM Studio’s server **running** whenever you use Copilot from the cloud.

**Alternative:** [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/) or ngrok on Windows exposes LM Studio over HTTPS; put that URL in `LLM_BASE_URL` and set `LLM_API_KEY` if you protect the tunnel — prefer **not** exposing LM Studio to the whole internet without TLS + auth.

## 6. Electron production

- **Build-time**: set `VITE_API_BASE_URL` before `npm run electron:dist` so the packaged app talks to GCP by default.
- **Runtime (no rebuild)**: place `quantumshield.config.json` next to the `.exe` (or under `resources/` when packaged) with:

  ```json
  { "VITE_API_BASE_URL": "https://YOUR_API_HOST/api/v1" }
  ```

  The main process injects this into the preload bridge; the web layer prefers it over the baked Vite env when present.

## 7. Files in this folder

| File | Purpose |
|------|---------|
| `env.cloud.example` | Template for GCP / container env (copy to Secret Manager or `/opt/quantumshield/.env` on the VM). |
| `cloudbuild.yaml` | Optional **Cloud Build** image build for Artifact Registry. |
| `startup-script.sh` | Example GCE startup: pull image and run container (edit image and env path). |

## 8. Smoke test

1. `GET https://YOUR_API_HOST/health`
2. Open static site → login → start a scan → confirm **WebSocket** progress (browser devtools → Network → WS).
3. Copilot / LLM: from GCE, `curl` your `LLM_BASE_URL` health or a minimal chat request to verify **Option A** or **Option B**.
