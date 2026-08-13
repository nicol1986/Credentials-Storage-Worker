# Password Safe Box Deployment Guide

This is a secure credential storage application built as a Cloudflare Worker. It provides a web interface to store and manage login credentials with encryption and authentication.

An encrypted credential vault deployed on **Cloudflare Workers** (single-file app). Credentials are encrypted in the browser with a key derived from your master password using AES-GCM. **The server only ever stores ciphertext** — it never sees your plaintext.

> Key change in v1.2: the backend storage moved from Workers KV to **D1 (SQLite)**, which is strongly consistent and supports transactions. Combined with frontend "optimistic updates", this fixes the occasional "saved but not showing up" issue from earlier versions.

---

## Features

- Login with a master password; JWT session issued by the backend.
- Each username/password is encrypted client-side; the server stores only ciphertext.
- Group tags with adjustable colors and display order.
- Group collapse/expand, sorting, and color labels.
- Export / Import backup (plain-text JSON, re-encrypted on import).
- Login history log (IP + time + status).

---

## How it works

1. **Login**: the browser derives an AES-GCM 256-bit key from your master password + `SALT` via PBKDF2 (SHA-256, 100k iterations). The backend only verifies `ACCESS_PASSWORD` and issues a JWT.
2. **Store**: each username/password is encrypted in the browser; the ciphertext JSON is stored in the D1 `credentials` table (`username`/`password` columns hold the ciphertext).
3. **Read**: the backend `SELECT`s from D1 and returns it; the browser decrypts locally.

> The decryption key depends on **master password + SALT**. As long as both stay the same, the ciphertext stays decryptable.

---

## Deploy (Dashboard)

1. Cloudflare Dashboard → **Workers & Pages** → **D1** → **Create database** (`safepass`).
2. Open the database → **Console** and run the schema below.
3. Create a Worker, paste `worker.js` over the default code, and **Deploy**.
4. Worker → **Settings → Variables and Secrets**:
  - **Secrets**: `ACCESS_PASSWORD` (your login password), `JWT_SECRET` (random long string).
  - **Variable** (optional): `SALT` (random string; strongly recommended).
5. Worker → **Settings → D1 database bindings** → add binding: variable name `DB` → select the `safepass` database.
6. **Redeploy** and open the Worker URL.

### Schema (required)

```sql
CREATE TABLE IF NOT EXISTS credentials (
  id          TEXT PRIMARY KEY,
  service     TEXT NOT NULL,
  username    TEXT NOT NULL,   -- ciphertext JSON
  password    TEXT NOT NULL,   -- ciphertext JSON
  grp         TEXT NOT NULL DEFAULT '未分组',
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_logs (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ip      TEXT,
  ts      INTEGER,
  status  TEXT
);
CREATE TABLE IF NOT EXISTS groups_meta (
  name        TEXT PRIMARY KEY,
  color       TEXT NOT NULL,
  sort_order  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_credentials_grp ON credentials(grp);
```

---

## Deploy (Wrangler CLI)

```bash
npm install -g wrangler
wrangler login
wrangler d1 create safepass
wrangler d1 execute safepass --remote --file=./migrations/0001_init.sql
wrangler secret put ACCESS_PASSWORD
wrangler secret put JWT_SECRET
wrangler deploy
```

`wrangler.toml`:

```toml
name = "safepass"
main = "worker.js"
compatibility_date = "2024-09-01"

[vars]
SALT = "your-custom-salt-string"

[[d1_databases]]
binding = "DB"
database_name = "safepass"
database_id = "your-database-id"
```

---

## Variables / Bindings

| Name | Type | Required | Notes |
| --- | --- | --- | --- |
| `ACCESS_PASSWORD` | Secret | Yes | Login master password |
| `JWT_SECRET` | Secret | Yes | JWT signing key (random long string) |
| `SALT` | Variable | No  | Key-derivation salt; defaults to a built-in value if unset (**set your own**) |
| `DB` | D1 binding | Yes | D1 database (holds `credentials` + `login_logs` tables) |

> v1.2 no longer needs any KV namespace.

---

## Migrating from v1.1 (KV)

The ciphertext format is unchanged (`{iv, data}`), so data migrates seamlessly via export/import:

1. On the **v1.1** instance → **Export Backup** → download `safepass-backup-*.json`.
2. On the **v1.2** instance → **Import Backup** → select the file.
3. The browser re-encrypts each entry with the current master password and writes it to D1 (group preserved).

> The backup file is **plain text** containing all your credentials. Delete or store it safely; do not upload it anywhere public.

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `env.DB.prepare is not a function` on login | `DB` is bound to a KV namespace, not a D1 database | Settings → **D1 database bindings** (not KV), name `DB`, pick your D1 db |
| `{"error":"D1 绑定缺失..."}` | D1 not bound or name ≠ `DB` | Same as above |
| `no such table: credentials` in logs | Schema not created | Run the schema SQL in the D1 Console |
| `Failed to process request` | Backend error | Check the Worker's **Logs / real-time logs** for the `detail` field |
| Login works but save fails | Secrets missing | Add `ACCESS_PASSWORD` / `JWT_SECRET` then redeploy |

---

## Security notes

- Set a random `SALT`; don't rely on the built-in default.
- Store `ACCESS_PASSWORD` / `JWT_SECRET` as **Secrets**, never in code or a repo.
- Writes use parameterized SQL (no injection). Ciphertext is still protected only by your master password; the server stores ciphertext only.
- Export backups are plain-text JSON — keep them safe.
- Suitable for personal/small-team self-hosting; not hardened with rate-limiting or brute-force protection. Don't store extremely sensitive credentials on an unhardened instance.
