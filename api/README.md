# Express Auth RBAC — Production-Ready Backend

A production-grade Node.js + Express REST API with JWT authentication, role-based access control (RBAC), PostgreSQL via Prisma ORM, and full Docker support.

---

## 📁 Folder Structure

```
app/
├── prisma/
│   ├── schema.prisma              # DB schema & Prisma config
│   ├── seed.js                    # Seed admin/analyst/user accounts
│   └── migrations/
│       └── 20240101000000_init/
│           └── migration.sql
├── src/
│   ├── config/
│   │   └── database.js            # Prisma client singleton
│   ├── controllers/
│   │   ├── auth.controller.js     # Auth HTTP handlers
│   │   └── user.controller.js     # User CRUD HTTP handlers
│   ├── middleware/
│   │   ├── authenticate.js        # JWT verification middleware
│   │   ├── authorize.js           # RBAC role-check middleware
│   │   ├── errorHandler.js        # Global error + 404 handler
│   │   └── validate.js            # express-validator rule sets
│   ├── routes/
│   │   ├── auth.routes.js         # /api/v1/auth/*
│   │   ├── user.routes.js         # /api/v1/users/*
│   │   └── analytics.routes.js    # /api/v1/analytics/*
│   ├── services/
│   │   ├── auth.service.js        # Auth business logic
│   │   └── user.service.js        # User business logic
│   ├── utils/
│   │   ├── AppError.js            # Custom error class
│   │   ├── jwt.js                 # Token generation & verification
│   │   ├── logger.js              # Winston logger
│   │   └── response.js            # Standardized response helpers
│   ├── app.js                     # Express app (middleware + routes)
│   └── server.js                  # Entry point + graceful shutdown
├── .dockerignore
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
└── package.json
```

---

## 🔐 Roles & Permissions

| Endpoint                        | USER | ANALYST | ADMIN |
|---------------------------------|:----:|:-------:|:-----:|
| POST /api/v1/auth/register      | ✅   | ✅      | ✅    |
| POST /api/v1/auth/login         | ✅   | ✅      | ✅    |
| POST /api/v1/auth/refresh       | ✅   | ✅      | ✅    |
| POST /api/v1/auth/logout        | ✅   | ✅      | ✅    |
| GET  /api/v1/auth/profile       | ✅   | ✅      | ✅    |
| GET  /api/v1/users              | ❌   | ❌      | ✅    |
| GET  /api/v1/users/:id          | ❌   | ✅      | ✅    |
| PATCH /api/v1/users/:id/role    | ❌   | ❌      | ✅    |
| DELETE /api/v1/users/:id        | ❌   | ❌      | ✅    |
| GET  /api/v1/analytics/summary  | ❌   | ✅      | ✅    |

---

## 🚀 Running with Docker (Recommended)

### 1. Clone & configure environment

```bash
cp .env.example .env
```

Edit `.env` and set strong secrets:

```env
JWT_SECRET=change-this-to-a-long-random-string-32-chars-min
JWT_REFRESH_SECRET=another-long-random-string-32-chars-min
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=authdb
```

### 2. Start everything

```bash
docker compose up --build
```

This starts:
- **postgres** — PostgreSQL 16 on port 5432
- **migrate** — runs `prisma migrate deploy` once
- **api** — Express server on port 3000

### 3. Seed the database (optional)

```bash
docker compose exec api node prisma/seed.js
```

Seeded accounts:

| Email                | Password       | Role    |
|----------------------|----------------|---------|
| admin@example.com    | Admin@1234!    | ADMIN   |
| analyst@example.com  | Analyst@1234!  | ANALYST |
| user@example.com     | User@1234!     | USER    |

---

## 🛠️ Running Locally (Without Docker)

### Prerequisites
- Node.js 20+
- PostgreSQL 14+ running locally

### Setup

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit DATABASE_URL and secrets in .env

# Generate Prisma client
npm run db:generate

# Run migrations
npx prisma migrate dev --name init

# (Optional) Seed
npm run db:seed

# Start dev server with hot reload
npm run dev
```

---

## 📡 API Reference

### Auth

```
POST /api/v1/auth/register
Body: { "name": "Alice", "email": "alice@example.com", "password": "Alice@1234!" }

POST /api/v1/auth/login
Body: { "email": "alice@example.com", "password": "Alice@1234!" }

POST /api/v1/auth/refresh
Body: { "refreshToken": "<token>" }

POST /api/v1/auth/logout
Headers: Authorization: Bearer <accessToken>

GET /api/v1/auth/profile
Headers: Authorization: Bearer <accessToken>
```

### Users (Admin/Analyst)

```
GET    /api/v1/users?page=1&limit=20&role=USER   # ADMIN only
GET    /api/v1/users/:id                          # ADMIN, ANALYST
PATCH  /api/v1/users/:id/role                     # ADMIN only
       Body: { "role": "ANALYST" }
DELETE /api/v1/users/:id                          # ADMIN only
```

### Analytics

```
GET /api/v1/analytics/summary    # ADMIN, ANALYST
```

### Health

```
GET /health    # Public — returns uptime + status
```

---

## 🔒 Security Features

- **Helmet** — sets secure HTTP headers
- **Rate limiting** — 200 req/15min globally; 20 req/15min on auth routes
- **bcrypt** — passwords hashed with configurable rounds (default: 12)
- **JWT access tokens** — short-lived (15m default)
- **JWT refresh tokens** — stored in DB, revoked on logout
- **Input validation** — express-validator on all inputs
- **Non-root Docker user** — runs as `nodeuser` (UID 1001)
- **No plain-text passwords** — ever stored or logged
- **User enumeration protection** — constant-time comparison on login

---

## 🏗️ Architecture Decisions

| Concern              | Solution                          |
|----------------------|-----------------------------------|
| ORM                  | Prisma (type-safe, migration-based)|
| Auth tokens          | Access + Refresh token pattern    |
| Error handling       | Centralized middleware + AppError |
| Logging              | Winston (JSON in prod, colored dev)|
| Validation           | express-validator rule sets       |
| Password hashing     | bcryptjs (pure JS, no native deps)|
| Graceful shutdown    | SIGTERM/SIGINT handlers           |
| Docker               | Multi-stage build, dumb-init      |
