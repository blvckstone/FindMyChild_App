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
npm run check      # every JavaScript file parses
npm run lint       # bug-focused rules (undefined references, dead code) — not style
npm test           # the full suite, against a real in-memory MongoDB
npm run build:css  # rebuild the stylesheet from the markup
npm run ci         # the checks and the suite, in the order CI runs them
```

`npm test` starts real server processes and several temporary databases, so it takes a couple of
minutes and needs no setup beyond `npm install`. The same commands run on every push and pull
request through `.github/workflows/ci.yml`, which additionally rebuilds the stylesheet and fails
if the committed copy is stale.

## Front-end assets

The user panel's Tailwind stylesheet is compiled ahead of time into `public/css/tailwind.css` and
served from this origin. **After adding or removing a utility class in `public/index.html`, run
`npm run build:css`** — otherwise the element renders unstyled, which the test suite catches
before CI does. It replaced `https://cdn.tailwindcss.com`, a third-party script that compiled CSS
in the visitor's browser and had full access to the page.

Responses carry a Content-Security-Policy that allows scripts, styles and connections from this
origin only (plus the two fonts hosts). It cannot stop injected inline code — the pages are built
from inline scripts — but it stops a script from another origin loading, and stops stolen data
being sent anywhere. Adding a new external service means adding it to the policy in `server.js`.

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
