# Project Libraries & Dependencies Overview

This document provides a comprehensive breakdown of all software libraries, packages, and frameworks used in the **QuantumShield — Quantum-Safe Cryptography Assessment System** (PNB Crypto Scanner), detailing their exact role and purpose across the backend, frontend, desktop shell, and testing suites.

---

## 📄 Table of Contents

1. [Backend Libraries (Python / FastAPI)](#backend-libraries-python--fastapi)
   - [Web & API Framework](#web--api-framework)
   - [Database & ORM](#database--orm)
   - [Security, Cryptography & Auth](#security-cryptography--auth)
   - [Network Probing & Protocol Scanning](#network-probing--protocol-scanning)
   - [Machine Learning & Quantum Risk Engine](#machine-learning--quantum-risk-engine)
   - [Report & PDF Generation](#report--pdf-generation)
   - [Configuration & Utilities](#configuration--utilities)
   - [Testing & Automation](#testing--automation)
2. [Frontend Libraries (React / Vite / TypeScript)](#frontend-libraries-react--vite--typescript)
   - [Core UI Framework & Architecture](#core-ui-framework--architecture)
   - [Desktop Shell & Packaging](#desktop-shell--packaging)
   - [UI Components, Primitives & Styling](#ui-components-primitives--styling)
   - [Data Visualization & Diagramming](#data-visualization--diagramming)
   - [State Management, Data Fetching & Forms](#state-management-data-fetching--forms)
   - [Client-Side PDF & Markdown Processing](#client-side-pdf--markdown-processing)
   - [Testing & Quality Assurance](#testing--quality-assurance)
3. [Library Role Summary Matrix](#library-role-summary-matrix)

---

## 🐍 Backend Libraries (Python / FastAPI)

Located under [`Backend/requirements.txt`](file:///a:/Hackathon/PNB%20-%20Crypto%20Scanner/Backend/requirements.txt).

### Web & API Framework

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`fastapi`** | `0.115.0` | Core high-performance ASGI web framework used for building all REST API endpoints, real-time WebSocket communication, dependency injection, and automatic Swagger/OpenAPI documentation. |
| **`uvicorn[standard]`** | `0.30.6` | Lightning-fast ASGI server implementation used to run and serve the FastAPI application asynchronously. |
| **`slowapi`** | `0.1.9` | Rate-limiting library for FastAPI endpoints to protect scan APIs against abuse and denial-of-service (DoS) conditions. |
| **`python-multipart`** | `0.0.12` | Streaming parser for handling multipart form data (used for uploading custom certificates, scan configurations, and domain files). |

### Database & ORM

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`motor`** | `3.5.1` | Asynchronous Python driver for MongoDB. Used to store semi-structured scan output, raw JSON payloads, CBOM (Cryptographic Bill of Materials), and certificate audit logs asynchronously. |
| **`pymongo`** | `4.8.0` | Synchronous underlying MongoDB driver required by Motor for database operations and query object definitions. |
| **`sqlalchemy[asyncio]`** | `2.0.36` | SQL toolkit and Object-Relational Mapper (ORM) using `asyncio` for relational database operations, structured user metadata, and relational data management. |
| **`asyncpg`** | `0.30.0` | High-performance, low-level asynchronous PostgreSQL database driver for Python. |
| **`alembic`** | `1.13.3` | Database schema migration tool for SQLAlchemy to manage PostgreSQL database migrations and schema evolution over time. |

### Security, Cryptography & Auth

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`cryptography`** | `43.0.1` | Core low-level cryptographic engine used for X.509 certificate parsing, RSA/ECC/PQC key size and algorithm inspection, ASN.1 parsing, and TLS handshake payload decoding. |
| **`python-jose[cryptography]`** | `3.3.0` | Implementation of JOSE (JSON Object Signing and Encryption) standard used for signing, encoding, and verifying JWT access tokens for user authentication. |
| **`passlib[bcrypt]`** & **`bcrypt`** | `1.7.4` / `3.2.2` | Secure password hashing library using the bcrypt hashing algorithm to hash and verify user passwords safely. |

### Network Probing & Protocol Scanning

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`dnspython`** | `>=2.4.0` | Pure-Python DNS toolkit used for custom DNS record inspection (CAA, MX, TXT, DNSSEC checks) without requiring external OS binaries. |
| **`python-nmap`** | `0.7.1` | Python wrapper for Nmap used to execute system-level port discovery, service detection, and network interface scans. |
| **`httpx`** | `0.27.2` | Asynchronous HTTP client for executing HTTP/HTTPS probes, HTTP security header verification, TLS renegotiation tests, and API interactions. |
| **`aiosmtplib`** | `3.0.2` | Asynchronous SMTP client library used to transmit automated security alerts, scheduled scan summaries, and compliance reports via email. |

### Machine Learning & Quantum Risk Engine

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`lightgbm`** | `>=4.3` | Gradient boosting framework used for training and executing quantum vulnerability scoring models and post-quantum migration risk forecasting. |
| **`scikit-learn`** | `>=1.3` | Machine learning toolkit providing feature scaling, risk classification models, and evaluation tools for cryptographic assessment. |
| **`onnx`** & **`onnxmltools`** | `>=1.15` / `>=1.12` | Open Neural Network Exchange format tools used to convert, serialize, and optimize trained ML models into standard ONNX format. |
| **`onnxruntime`** | `>=1.17` | High-performance cross-platform runtime engine used to execute ONNX machine learning models for real-time quantum safety scoring. |
| **`numpy`** | `>=1.24` | Fundamental scientific computing library used for matrix operations, numerical processing, and data preparation in ML models. |
| **`joblib`** | `>=1.3` | Lightweight pipeline serialization tool used for loading pre-trained scikit-learn transformers and ML model artifacts. |

### Report & PDF Generation

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`reportlab`** | `4.2.5` | Open-source PDF generation engine used on the backend to dynamically generate downloadable executive security reports, cryptographic audit reports, and compliance certificates. |

### Configuration & Utilities

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`pydantic`**, **`pydantic[email]`** | `2.9.2` | Data validation, type enforcement, and schema definition library for API request/response payloads and email formatting validation. |
| **`pydantic-settings`** | `2.5.2` | Hierarchical configuration management reading environment variables from `.env` files and system environments. |
| **`email-validator`** | `2.2.0` | Strict email address validation library integrated into Pydantic models. |
| **`python-dotenv`** | `1.0.1` | Environment variable loader that reads settings from `.env` configuration files into `os.environ`. |

### Testing & Automation

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`pytest`** | `8.3.4` | Automated testing framework used to run backend unit tests, integration tests, and API endpoint tests. |
| **`playwright`** | `>=1.40.0` | Browser engine automation tool used optionally for deep client-side TLS inspections and browser end-to-end testing. |

---

## ⚛️ Frontend Libraries (React / Vite / TypeScript)

Located under [`Frontend/package.json`](file:///a:/Hackathon/PNB%20-%20Crypto%20Scanner/Frontend/package.json).

### Core UI Framework & Architecture

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`react`** & **`react-dom`** | `^18.3.1` | Core UI library providing declarative component-based user interface architecture for the dashboard and desktop client. |
| **`typescript`** | `^5.8.3` | Static type checker enforcing type safety across components, API contracts, forms, and data structures. |
| **`vite`** & **`@vitejs/plugin-react-swc`** | `^6.4.1` / `^3.11.0` | Fast build tool and development server leveraging SWC (Speedy Web Compiler) for instant HMR and optimized production bundles. |

### Desktop Shell & Packaging

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`electron`** | `^41.2.1` | Cross-platform desktop application container wrapping the Vite React web application into a standalone desktop application. |
| **`electron-builder`** | `^26.8.1` | Packaging and installer generator for producing native Windows (NSIS installers), macOS (DMG), and Linux (AppImage) executables. |
| **`concurrently`**, **`cross-env`**, **`wait-on`** | Various | Developer utilities for cross-platform environment execution, orchestration of simultaneous Vite dev server and Electron process launches. |

### UI Components, Primitives & Styling

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`tailwindcss`**, **`postcss`**, **`autoprefixer`** | `^3.4.17` | Utility-first CSS engine and pre-processors for fast custom UI styling, responsive layouts, and dark mode themes. |
| **`@radix-ui/react-*`** | `^1.x` | Accessible, unstyled UI primitives (Dialogs, Accordions, Dropdown Menus, Tabs, Tooltips, Scroll Areas, Select, Popovers, Switches, Toasts, Sliders, Context Menus). |
| **`lucide-react`** | `^0.462.0` | Vector icon library providing clean icons for security metrics, status indicators, navigation, and cryptographic findings. |
| **`framer-motion`** | `^12.36.0` | Motion and animation framework powering UI transitions, modal animations, collapsible drawers, and micro-interactions. |
| **`next-themes`** | `^0.3.0` | Dark and light theme switcher managing CSS theme classes seamlessly. |
| **`vaul`** | `^0.9.9` | Drawer primitive for rendering slide-over details panels for certificate findings and detailed CBOM rows. |
| **`cmdk`** | `^1.1.1` | Command menu / palette primitive enabling quick keyboard search (`Ctrl+K`) for scans, domains, and settings. |
| **`clsx`**, **`tailwind-merge`**, **`class-variance-authority`** | Various | Dynamic CSS class composition utilities to combine and deduplicate Tailwind CSS classes safely without specificity conflicts. |

### Data Visualization & Diagramming

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`recharts`** | `^2.15.4` | Composability-driven chart library used to render interactive compliance score gauges, historical vulnerability trends, risk pie charts, and algorithm distribution bar charts. |
| **`@xyflow/react`** (React Flow) | `^12.10.1` | Node-based workflow diagram library used to render interactive cryptographic dependency trees, certificate trust chains, and network topology maps. |
| **`mermaid`** | `^11.14.0` | Diagramming and charting tool that renders markdown-defined sequence diagrams and flowcharts for PQC migration path workflows. |

### State Management, Data Fetching & Forms

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`@tanstack/react-query`** | `^5.83.0` | Asynchronous state management and caching library managing backend API calls, background polling, and cache invalidation. |
| **`axios`** | `^1.13.6` | Promise-based HTTP client for API calls with built-in token authentication interceptors and error handling. |
| **`react-router-dom`** | `^6.30.1` | Declarative routing library managing single-page application view transitions. |
| **`react-hook-form`** & **`@hookform/resolvers`** | `^7.61.1` | Form state management library providing fast, un-rendered form inputs integrated with Zod validation. |
| **`zod`** | `^3.25.76` | Schema declaration and validation library enforcing client-side validation rules for user input and configuration schemas. |

### Client-Side PDF & Markdown Processing

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`jspdf`** & **`jspdf-autotable`** | `^4.2.1` / `^5.0.7` | Client-side PDF generation library for generating and exporting scan reports, tables, and certificate audit summaries directly from the browser/Electron app. |
| **`react-markdown`**, **`remark-gfm`**, **`rehype-raw`**, **`rehype-sanitize`** | Various | Markdown parser and HTML sanitizer pipeline used to safely render vulnerability remediation guides, CVE summaries, and compliance documentation. |

### Testing & Quality Assurance

| Library | Version | Project Role & Description |
| :--- | :--- | :--- |
| **`vitest`** | `^3.2.4` | Fast unit test runner designed specifically for Vite projects. |
| **`@testing-library/react`** & **`@testing-library/jest-dom`** | Various | React component testing utilities for testing user interaction and DOM state. |
| **`jsdom`** | `^28.1.0` | Headless DOM environment for running frontend unit tests inside Node.js. |
| **`@playwright/test`** | `^1.57.0` | End-to-end testing library for verifying cross-browser desktop and web app user flows. |
| **`eslint`** & plugins | `^9.32.0` | Code quality enforcement and linting setup for TypeScript and React code conventions. |

---

## 📊 Library Role Summary Matrix

| Category | Primary Libraries Used | Key Responsibility in QuantumShield |
| :--- | :--- | :--- |
| **API & Backend Core** | `FastAPI`, `Uvicorn`, `Pydantic` | High-throughput asynchronous REST API & WebSocket server for processing security scans. |
| **Data Persistence** | `Motor` (MongoDB), `SQLAlchemy` (PostgreSQL), `Alembic` | Hybrid storage: MongoDB for raw scan JSON/CBOMs & PostgreSQL for structured user/audit data. |
| **Security & Crypto Probes**| `cryptography`, `dnspython`, `python-nmap`, `httpx` | Parsing certificates, inspecting cipher suites, verifying DNS records, and conducting port probes. |
| **Quantum AI Risk Engine** | `LightGBM`, `Scikit-Learn`, `ONNX Runtime`, `NumPy` | Machine learning engine for calculating quantum vulnerability scores and PQC migration readiness. |
| **Backend Reporting** | `ReportLab` | Automated backend PDF generation for compliance and audit certificates. |
| **Desktop Shell** | `Electron`, `Electron Builder` | Native cross-platform desktop wrapper for Windows/macOS/Linux. |
| **Frontend Framework** | `React 18`, `TypeScript`, `Vite` | Ultra-fast SPA interface with full static type safety. |
| **UI Components & CSS** | `Radix UI`, `Tailwind CSS`, `Framer Motion`, `Lucide Icons` | Accessible, animated, modern dark-themed dashboard design system. |
| **Visualizations** | `Recharts`, `React Flow` (`@xyflow/react`), `Mermaid` | Risk breakdown graphs, CBOM dependency trees, and PQC migration flowcharts. |
| **Data Management** | `TanStack React Query`, `Axios`, `React Hook Form`, `Zod` | Server state caching, API integration, and schema-validated user forms. |
