# Find My Child

Backend, user panel and admin panel for the Find My Child missing-child platform. One Express
server serves the API, both front ends and the realtime (socket.io) channel.

## Running it

```bash
cp .env.example .env      # then fill in the values (see below)
npm install
npm start                 # http://localhost:8080  (user panel), /admin (admin panel)
```

`npm run dev` does the same with auto-restart on file changes.

The server prints a startup audit that names any missing critical variable, so a misconfigured
deploy says so in the logs rather than failing later:

```
[STARTUP] Shared: sessions, rate-limit counters, AI match pool (MongoDB). Per-instance: socket fan-out — needs a Redis adapter at >1 replica.
[STARTUP] CORS: same-origin only (set ALLOWED_ORIGINS to add browser clients).
```

Without a reachable `DB_ATLAS` the process still starts and serves the pages — `/api/health`
reports `degraded` — but anything that reads or writes data fails.

## Checks

```bash
npm run check   # every JavaScript file parses
npm run lint    # bug-focused rules (undefined references, dead code) — not style
npm test        # the full suite, against a real in-memory MongoDB
npm run ci      # all three, in the order CI runs them
```

`npm test` starts real server processes and several temporary databases, so it takes a couple of
minutes and needs no setup beyond `npm install`. The same three commands run on every push and
pull request through `.github/workflows/ci.yml`.

## Configuration

Every variable is documented in `.env.example`. The short version: `DB_ATLAS` and `JWT_SECRET`
are required; Cloudinary is needed for photo uploads, Resend for signup OTP, and Google is
optional for sign-in. Leaving an optional group unset disables just that feature.

## Deployment

Hosted on Northflank, which supplies the environment variables from its dashboard. `render.yaml`
is a portable blueprint and the reference list of required variables, not the live configuration.

Two things to know before scaling beyond one instance:

- Login sessions, rate-limit counters and the AI match pool are shared through MongoDB, so a
  second replica agrees on who is logged in and how many attempts a client has made.
- Socket notifications are still broadcast per process, so a client connected to replica A does
  not hear replica B's updates. Attach the socket.io Redis adapter first — see `SCALING.md`.

## Documentation

- `SCALING.md` — what is shared between instances, what is not, and the environment variables
  that shape performance and limits.
- `Changes.txt` (repository root) — the product bug list.
