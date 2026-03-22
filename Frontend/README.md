# QuantumShield Frontend — Quantum‑Safe Cryptography Assessment System (QSCAS)

Banking-grade cybersecurity dashboard UI for the **Quantum‑Safe Cryptography Assessment System**.

## Tech stack

- React + TypeScript (Vite)
- TailwindCSS + shadcn/ui
- Recharts (charts)
- Axios (API)

## Quick start (Windows)

```bash
cd Frontend
npm install
```

Create `Frontend/.env`:

```env
# Backend API base URL (FastAPI v2 mounted at /api)
VITE_API_BASE_URL=http://localhost:8000/api
```

Run dev server:

```bash
npm run dev
```

Open: `http://localhost:8080`

## Kali backend connectivity (Windows → Kali VM)

If your backend runs on Kali and frontend runs on Windows, set:

```env
VITE_API_BASE_URL=http://<kali-ip>:8000/api
```

Then restart `npm run dev` (Vite reads env only at startup).

## Auth + RBAC

- Login uses the backend `/api/login` and stores the JWT in `sessionStorage`
- RBAC roles: `admin`, `employee`
  - `Reporting` page is **admin-only** (hidden + route guarded)
