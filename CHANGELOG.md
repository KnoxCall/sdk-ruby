# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

**First release: 1.0.0, 2026-09-27** — published to RubyGems as `knoxcall` (monorepo tag `knoxcall-ruby-v1.0.0`).

Release headings take the form `## [X.Y.Z] — YYYY-MM-DD`.
`tests/coverage/sdk-changelog-honesty.test.ts` refuses any release heading that
has no matching git tag, so this file cannot claim a release that did not happen.

## [Unreleased]

### Changed
- **1.1.0 — registry install instructions; `KnoxCall::VERSION` now matches the gem.** A registry renders the README that was inside the version it published and never lets it be edited, so the README inside the previous release still showed pre-release install instructions (build from a source checkout) after the package was live; the corrected README reaches a registry only as a new version. `KnoxCall::VERSION` said `0.1.0` inside gem 1.0.0, so every request carried the User-Agent `knoxcall-ruby/0.1.0` and every uncovered-egress report said `ruby/0.1.0`; both now say `1.1.0`. The version is a minor, not a patch: the `Retry-After` change below adds `ServerError#retry_after`, which is new public API.
- **`Retry-After` is honoured on a 503, not only on a 429.** KnoxCall now answers a request it could not serve because one of its own dependencies did not answer in time with `503 { error: { type: "dependency_unavailable", … } }` + `Retry-After` (on the data plane this used to surface as an opaque `401 Unauthorized`; on `/v1` as `500 internal_error`). `ServerError` exposes the header as `#retry_after` (`nil` when none was sent), and the retry loop waits it — capped at 30 s — before the next attempt, exactly as it does for a 429; a plain 5xx with no header keeps the jittered backoff. Nothing to change in calling code: it is a retryable server error, never an authentication failure, and never a manifest-refresh trigger. (PARITY §4, §16.)

## [1.0.0] — 2026-09-27

### Changed
- **Refusal-driven refresh learns the 404.** The route data plane now answers an AUTHENTICATED credential's call to a Route that does not resolve with `404 {"error":{"type":"route_not_found"|"environment_not_configured"|"environment_disabled","message","request_id"}}` plus the KnoxCall response block, instead of the opaque `401 Unauthorized` (which callers the tenant has not authenticated keep — founder decision 2026-09-26, PARITY §21). `wrap.faraday_connection(routes: :auto)`, `wrap.faraday_middleware` and `wrap.intercept!` now treat a KnoxCall-origin `404` whose envelope `error.type` is `route_not_found` as a refresh trigger alongside the 401 — a stale manifest naming a deleted Route is exactly that — refreshing once and re-deciding once, never looping (`KnoxCall::RouteRefusal`). The `environment_*` types are surfaced as-is; an UPSTREAM 404 (`X-Knox-Upstream-Status` present) never triggers it, whatever its body says. `on_refused` reports `status: 404` for that case. `call` is unchanged: it returns the 404 raw (PARITY §5) and spends no re-mint on it. Cross-language contract: `sdk/fixtures/route-refusal.json`.

### Added
- **Uncovered-egress observations (PARITY §21.3), on by default.** `wrap.intercept!` and `wrap.faraday_middleware` (and `faraday_connection(routes: :auto)`) now count calls sent direct because their host is `:unlisted` while they carry a credential-bearing header — host, first path segment, method and the header NAME; never the value, the query string or the body — and report them to `POST /v1/wrap/egress-observations` about once a minute (a background thread; at 200 distinct keys at once; once more on `uninstall`/`stop`). Opt out with `observe_uncovered: false` or `KNOXCALL_OBSERVE_UNCOVERED=off`; nothing is reported while `KNOXCALL_INTERCEPT=off`; a 403 stops reporting with one warning. New `on_observation_flush:` hook, `wrap.report_egress_observations(observations)`, `KnoxCall::EgressObservations`, `KnoxCall::EgressObservationReporter`. (Founder decision 2026-09-26: default-on with an opt-out.)
- **A credential in the path is never reported.** Before an uncovered-egress observation is sent, a first path segment that looks like a credential (Telegram's `/bot<id>:<secret>`, a Stripe/GitHub/AWS/Google/Slack/JWT token, any segment over 64 characters, or a 24+ character mixed-class run — raw or percent-decoded) is reported as `/`; the server's identical rule (#1022) counts it under the receipt's new `redacted` field, now on the report type. (PARITY §21.3.)
- `knox.wrap.intercept_manifest(if_none_match:)` — the conditional poll. Pass the manifest `version` you hold and the SDK sends `If-None-Match: W/"<version>"` (`KnoxCall::Resources::Wrap.manifest_etag`); the server's `304` returns `nil` — keep what you hold (the unconditional call never returns `nil`). The route-aware store (`wrap.intercept!`, `wrap.faraday_connection(routes: :auto)`, `wrap.faraday_middleware`) now polls this way on every refresh after the first, lazy or forced: a `304` keeps the manifest, restarts the TTL clock, clears backoff and fires no `on_refresh`, so a steady-state poll costs no body bytes. A `manifest_fetch` callable without an `if_none_match:` keyword keeps polling unconditionally. `Client#request` gained `allow_not_modified:` (internal; answered with `Client::NOT_MODIFIED`). Auth, the one re-auth on 401 and retries are unchanged. (PARITY §21.1 "Conditional poll"; fixture `sdk/fixtures/intercept-store-conditional.json`.)
- **Origin marker on rerouted calls.** Every route-mode send from `wrap.intercept!` / `wrap.faraday_connection(routes: :auto)` / `wrap.faraday_middleware` (and the legacy explicit `route:` form) now carries `x-knoxcall-origin: sdk-intercept`, so the API Log shows the call as **SDK intercept** rather than **Direct** (`client_origin` on request-log rows: `direct` | `sdk_intercept`). A direct `call` / bound route sends nothing; an ephemeral hop sends nothing. A caller-supplied `x-knoxcall-origin` in `call` / `ephemeral` `headers:` is stripped like the proxy-auth headers — the server treats the marker as informational either way. The seam is `call`'s internal `_origin:` keyword (only `Client::SDK_INTERCEPT_ORIGIN` is accepted; anything else raises `ArgumentError`). (PARITY §21.2.)
- **Route-aware interception.** `wrap.intercept!(hosts: [...])` — an opt-in, experimental process-wide seam (founder decision D7) that prepends `Net::HTTP#request` and sends each request through the Route that covers its host + path (the Route injects the secret; no provider credential travels), through the ephemeral proxy for listed hosts no Route covers, and untouched otherwise (decision D2). Reaches Faraday's default adapter, `rest-client`, `httparty`, raw Net::HTTP; not Typhoeus / Curb / `http.rb`. Returns a handle with `uninstall`, `ready`, `refresh`, `manifest`; a second install raises. `wrap.faraday_connection(routes: :auto)` gives an injected connection the same decisions (default stays `:off`; controls on `conn.knoxcall`); new `wrap.faraday_middleware(hosts: [...])` for a stack an SDK builds itself. The manifest is refreshed lazily at its TTL (no background thread). New options: `hosts:` (Array or per-host Hash with `credential:` / `unavailable:`), `unavailable: :direct` (transit only — route mode and escrow always fail closed, D4), `require_context:` + `wrap.routed { }`, and the hooks `on_reroute`, `on_refresh`, `on_manifest_error`, `on_unmatched_path`, `on_refused`, `on_fallback`; a typo'd `on_*` keyword or a non-bare host raises. `KNOXCALL_INTERCEPT=off` is the kill switch. New `KnoxCall::InterceptResolver`, `InterceptManifestStore`, `InterceptPipeline`, `InterceptContext`, `Intercept`. `Client#base_url`, `#proxy_base_url`, `#environment` readers. (route-aware-interception-plan.md PR5; PARITY §21.1.)
- `wrap.intercept_manifest(environment: nil)` — `GET /v1/wrap/intercept-manifest`, the per-environment list of upstream hosts an intercept-enabled Route covers (`"version"` doubles as the ETag). What a route-aware interceptor polls (route-aware-interception-plan.md PR1). `intercept_enabled:` is accepted by `routes.create/update/upsert_environment` and echoed on reads.

### Fixed
- `wrap.intercept!` no longer opens a TCP (and TLS) connection to the real upstream for a request it is about to reroute. `Net::HTTP` connects in `start`, before the `request` seam ran, so an intercepted host that was unreachable from the process failed with `ECONNREFUSED` before KnoxCall was ever asked — found by the CI smoke, where the echo lives on the runner's loopback and the container's loopback refuses. The seam now also covers `connect`: a host the decision table would reroute defers its connection, and a request that ends up direct (unlisted, route-around, the kill switch, the `unavailable: :direct` fallback) connects at that moment.
- `call` — and bound routes, the CLI and the interceptors' route mode, which delegate to it — now places the upstream path under the tenant host's `/api` data-plane entry point whenever the proxy base is a KnoxCall cloud tenant host with no path of its own (derived, or an explicit override naming one); any other base is used verbatim. Before, `client.call("r", path: "/users")` sent `https://{tenant}.knoxcall.com/users`, which a tenant host answers with the dashboard, not the proxy — every documented example was affected, and `path: "/api/…"` was the only form that worked. `path` is now always the upstream path (PARITY §5).
- `call` / `ephemeral` no longer spend their one token re-mint on an UPSTREAM 401 relayed by the data plane: a response carrying `X-Knox-Upstream-Status` (the route data plane's response block) or `X-Knox-Destination-Status` (the ephemeral proxy) is the upstream's answer and is returned as-is. Mirrors the Node, Python and Go fix.
- `WrapTransport.normalize_host` now also strips surrounding whitespace and IPv6 brackets (PARITY §21's host contract).

The package's behaviour is specified by [`sdk/PARITY.md`](../PARITY.md), which is
authoritative over this file for anything describing current behaviour.

### Added

- `KnoxCall::WorkloadCredentialProvider` — caches a workload-identity capability
  token and refreshes it on a two-tier schedule (advisory at expiry-120s, mandatory
  at expiry-30s), calling the `assertion:` source before every exchange. Because
  KnoxCall assertions are single-use, a source that returns bytes already spent is
  refused locally with `KnoxCall::StaleAssertionError` rather than sent and refused
  as a replay. Thread-safe: N concurrent callers cause one exchange. PARITY
  section 20.

### Owed at first release

- Replace the local-path / `git` install in the public docs with a **pinned**
  registry install (`gem "knoxcall", "~> X.Y"`) — see `sdk/PARITY.md` §"Documented installs must
  pin a version".
- Write the first `## [X.Y.Z] — YYYY-MM-DD` heading, and tag it.
