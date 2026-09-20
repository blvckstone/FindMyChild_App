# Scaling notes

What is shared between server instances, what is not, and what to change before running more
than one replica. Written after the Phase 3 work (C2 broadcast storm, C3 admin queries, G1
shared state); see `tests/` for the tests that pin each claim.

## Shared already

| State | Where it lives | Why it matters |
|---|---|---|
| Sessions (user login tokens) | `Session` collection in MongoDB, TTL index on `expiresAt` | A login minted on replica A works on replica B; blocking or deleting an account revokes the session on every replica; a restart no longer logs everyone out. |
| Admin auth | Signed JWT for transport **plus** an admin row in the same `Session` collection (`kind: 'admin'`) | The token's signature is checked, but access also requires a live session — so logging out, removing an admin from the whitelist, or changing their role/permissions takes effect on the next request instead of when the 7-day token expires. The JWT alone is *not* sufficient. |
| AI face match pool | Cached in each instance, but rebuilt from MongoDB and invalidated on every API write | Each instance compares the same records. |
| Rate limit counters | `RateLimit` collection in MongoDB, TTL index on `resetAt` | The ceiling is global instead of per replica, and a deploy does not clear an attacker's progress on the admin login. If the database is unreachable the store counts per process (`functions/rateLimitStore.js`) — it never disables the limit and never fails the request. |
| All application data | MongoDB Atlas | Single source of truth. |
| Change notifications | Coalesced, scoped event (`dataChanged` with `{ scopes }`) | One notification per window instead of one per write. |

## Still per instance

| State | Consequence | Fix before scaling out |
|---|---|---|
| socket.io fan-out | A client connected to replica A does not receive notifications triggered on replica B. It still converges: the panel re-fetches on tab switches and the user panel polls with a jittered 30 s safety net. | Attach the socket.io Redis adapter (`@socket.io/redis-adapter`) and set `REDIS_URL`. |
| Public data cache (`dataCache`, 30 s TTL) | Another replica's write does not clear this replica's cache, so a listing can be up to 30 s stale. | Drop the cache (every listing query is index-backed now) or move invalidation to a shared version counter. |
| Verified-signup map (`verifiedSignups`, 15 min) | A signup verified on replica A must be completed on replica A. | Store the verification flag with the signup record in MongoDB. |
| Coalescing window (`changeNotifier`, 750 ms) | Windows are per instance, so N replicas can emit up to N notifications per burst. | Harmless; a Redis adapter plus a shared window removes the duplication if it ever matters. |

## Environment variables that shape this

| Variable | Default | Purpose |
|---|---|---|
| `SESSION_TTL_MS` | 30 days | Session lifetime. Tokens previously never expired. |
| `FACEMATCH_MAX_POOL` | 20000 | How many descriptors stay in each instance's memory (~512 B each). Records beyond it are streamed per scan, so a larger pool costs memory, never correctness. |
| `FACEMATCH_POOL_TTL_MS` | 5 min | How long an instance may serve a stale match pool after an out-of-band edit. |
| `SOCKET_QUERY_LIMIT` | 60 | Realtime queries one socket connection may run per window. The sockets are anonymous, so this is the ceiling that keeps one client from looping database queries. |
| `SOCKET_QUERY_WINDOW_MS` | 60 s | Length of that window. |
| `SOCKET_MAX_IN_FLIGHT` | 4 | How many realtime queries one connection may have running at once; a client that pipelines without waiting is refused rather than queued. |
| `DEBUG_SOCKET` | unset | Set to `1` to log socket connections and per-event activity. Off by default: realtime request payloads are user data and are never logged. |
| `ALLOWED_ORIGINS` | unset (same-origin only) | Comma-separated hosts or origins allowed to call the API from a browser. Unset means only requests whose Origin matches the Host serving them are answered with CORS headers — which is all this app needs, since one server serves both panels. Set `*` only if you deliberately want any website to be able to call it. |

## Anonymous realtime traffic

The realtime API is deliberately usable without an account (the home page lists public records
with it), so it is guarded rather than authenticated: `functions/realtimeGuard.js` validates every
payload into an allow-listed shape before a query sees it (`functions/realtimeGuard.js` drops
unknown keys, caps text, requires real ISO dates and known enum values) and gives each connection
a query budget plus a cap on queries in flight. Per-connection, not global, so one abusive client
cannot starve the others. Every refusal is answered on the event the client is already listening
for, so an older client degrades quietly.

## Browser origins

Responses carry CORS headers only for the origin that served the page (`functions/origins.js`).
Previously every response advertised `Access-Control-Allow-Origin: *` and socket.io advertised
`origin: "*"`, so any website could call the API from a visitor's browser and read the reply. Add
a browser client that lives on another host through `ALLOWED_ORIGINS` rather than by widening the
default. The socket handshake applies the same rule and also refuses a cross-origin browser
outright (requests with no Origin — curl, health probes, a native app — are allowed, because CORS
exists to constrain browsers).

## Uploads

Every uploaded image is verified before any route sees it (`functions/imageValidation.js`, called
from the `validateUploads` middleware in `server.js`): the magic numbers must be a JPEG/PNG/WEBP/GIF
signature, the declared MIME type must agree with the bytes, `sharp` must be able to decode it, its
dimensions must stay under 8000 px and 40 MP, and it is then re-encoded. The re-encode is what
actually removes the old trust in a client-chosen content type: it drops EXIF (including GPS),
strips trailing content, and caps the stored image at 1600 px. Because the check lives in
middleware, a new upload endpoint inherits it. Validating costs CPU per upload, so a burst of large
uploads is the one thing to watch on a small container — resize-client-side before changing this.

## Verifying a multi-replica setup

The tests in `tests/multiInstance.db.test.js` start two real server processes against one
database and assert that a login works on both, that a restart does not log users out, and that
blocking an account on one instance rejects its tokens on the other.

`tests/transport.db.test.js` covers the transport rules against the real server: same-origin is
allowed and a foreign site is not (HTTP and socket handshake alike), an explicitly listed origin
is allowed, the removed admin debug route is gone, and a non-image upload is refused with a 400
before the route runs. `tests/imageValidation.test.js` and `tests/origins.test.js` cover the two
modules directly.
