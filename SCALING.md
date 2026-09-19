# Scaling notes

What is shared between server instances, what is not, and what to change before running more
than one replica. Written after the Phase 3 work (C2 broadcast storm, C3 admin queries, G1
shared state); see `tests/` for the tests that pin each claim.

## Shared already

| State | Where it lives | Why it matters |
|---|---|---|
| Sessions (user login tokens) | `Session` collection in MongoDB, TTL index on `expiresAt` | A login minted on replica A works on replica B; blocking or deleting an account revokes the session on every replica; a restart no longer logs everyone out. |
| Admin auth | Signed JWTs (`JWT_SECRET`) | Stateless verification, no shared store needed. |
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

## Verifying a multi-replica setup

The tests in `tests/multiInstance.db.test.js` start two real server processes against one
database and assert that a login works on both, that a restart does not log users out, and that
blocking an account on one instance rejects its tokens on the other.
