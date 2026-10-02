# knoxcall-ruby

Official KnoxCall API client for Ruby. Standards-based OAuth 2.1 + DPoP (RFC 9449) under the hood, zero dependencies (stdlib only) — your code just calls methods. Ruby >= 3.1.

## Install

```ruby
# Gemfile
gem "knoxcall", "~> 1.0"
```

## Quickstart

```ruby
require "knoxcall"

# Credentials inline — tenant auto-discovered from the credential.
client = KnoxCall::Client.new(client_id: "tk_xxxxxxxx", client_secret: "...")

# Or zero-arg with the environment configured
# (KNOXCALL_TENANT, KNOXCALL_CLIENT_ID, KNOXCALL_CLIENT_SECRET):
client = KnoxCall::Client.new

# A management call…
page = client.routes.list
puts "#{page['meta']['total']} routes"

# …and a data-plane call through a route (slug preferred).
res = client.call("api-orders", path: "/v1/customers")
customers = JSON.parse(res.body)
```

The client is Mutex-safe: share a single instance across Puma / Sidekiq threads.

## Authentication

Pass credentials as flat constructor options:

| Option | Use |
|---|---|
| `client_id:` + `client_secret:` | OAuth client-credentials grant (recommended for servers) |
| `access_token:` / `api_key:` | a pre-acquired token or key — works with `kc_…` tokens and legacy `tk_…`/`AKE…` keys (two spellings, one behavior) |
| `bootstrap:` | advanced: `ClientCredentials`, `AccessToken`, `OIDCTokenExchange` (workload identity), `StoredCredentials` (a specific credentials file/profile) |

Passing conflicting credential options (e.g. `api_key:` and `client_id:`) raises `ArgumentError` at construction. Explicit options always beat the environment.

With no explicit credentials, the SDK resolves from the environment in priority order:

1. `KNOXCALL_ACCESS_TOKEN` (or `KNOXCALL_API_KEY`) env var
2. Credentials file written by `knoxcall login` (`~/.knoxcall/credentials.json`)
3. `KNOXCALL_CLIENT_ID` + `KNOXCALL_CLIENT_SECRET`

### Log in once with the CLI

This gem ships the `knoxcall` CLI (`gem install knoxcall`). It signs you in
once in your browser; every script and worker on the machine picks the
credential up automatically. No env vars, no keys in code:

```bash
knoxcall login                    # opens your browser (PKCE); prints the URL too
knoxcall login --device           # headless/SSH machines: device-code flow
knoxcall login --profile staging  # keep multiple accounts side by side
knoxcall whoami                   # show the signed-in tenant
knoxcall init                     # wrap-onboarding: confirm tenant + print a quickstart
knoxcall logout                   # revoke and remove the stored credential
```

`knoxcall init` gets you wrapping a provider SDK. With no `--provider` it
confirms who you are signed in as and prints a two-step quickstart (no writes).
With `--provider stripe --secret-name wrap-stripe --host api.stripe.com` it moves
a provider key into KnoxCall custody and prints the gateway `base_url` to point
your SDK at — the key is read from the `KNOXCALL_WRAP_SECRET` env var (never a
flag, so it stays out of your shell history) and is never printed. It works
against the tenant you are already signed in to; it does not provision a tenant.

Every KnoxCall SDK (python, node, go, php — and this gem) ships the same
`knoxcall` executable with the same commands, writing the same
`~/.knoxcall/credentials.json`, and every SDK reads that file — log in once
with whichever CLI is on your PATH and all of them are signed in. Two SDKs
installed side by side colliding on the executable name is harmless by
construction.

```ruby
client = KnoxCall::Client.new  # zero config — tenant and base URL come from the login
routes = client.routes.list
```

Credentials are stored in `~/.knoxcall/credentials.json` (file mode 0600). The
stored tenant and base URL seed the client automatically; explicit constructor
options or env vars always win. Access tokens refresh themselves, and refreshes
are cross-process safe (file lock + atomic rotation of the single-use refresh
token). If a refresh fails because the credential was revoked or expired, the
SDK raises `AuthenticationError` telling you to run `knoxcall login` again.
Select a non-default profile with `KNOXCALL_PROFILE` (or
`bootstrap: KnoxCall::StoredCredentials.new(profile: "staging")`).

### Environment variables

| Variable | Meaning |
|---|---|
| `KNOXCALL_TENANT` | tenant slug (optional — auto-discovered from the credential when unset) |
| `KNOXCALL_ENVIRONMENT` | default environment for data-plane calls |
| `KNOXCALL_CLIENT_ID` / `KNOXCALL_CLIENT_SECRET` | client-credentials grant |
| `KNOXCALL_ACCESS_TOKEN` / `KNOXCALL_API_KEY` | pre-acquired token (ACCESS_TOKEN wins) |
| `KNOXCALL_BASE_URL` | management API base override (legacy alias: `KNOXCALL_API_BASE_URL`) |
| `KNOXCALL_PROXY_BASE_URL` | data-plane base override |
| `KNOXCALL_CREDENTIALS_FILE` | credentials file path override (default `~/.knoxcall/credentials.json`) |
| `KNOXCALL_PROFILE` | credentials-file profile to use (default `default`) |

Pass `sandbox: true` to target the isolated Test data plane (`sandbox.knoxcall.com` management host, `sandbox-{tenant}.knoxcall.com` proxy host) with a `tk_test_` key.

### Security notes

- **A pre-acquired `access_token:` / `api_key:` is not auto-renewed.** It carries no refresh token, so the SDK sends it as-is until the server rejects it with a 401 — there is no silent refresh. For durable, self-renewing auth use `client_id:` + `client_secret:` (client-credentials) or log in with `knoxcall login` (the stored refresh token is rotated for you under a cross-process lock).
- **Plaintext transport is flagged.** If the resolved management base URL *or* the data-plane proxy URL is `http://` to a non-loopback host, the client emits a one-time warning to `$stderr` that credentials and tokens will be sent unencrypted. `http://localhost` (and other loopback addresses) is the normal dev case and stays silent — use `https://` everywhere else.
- **Loose credentials-file permissions are flagged.** On POSIX, if `~/.knoxcall/credentials.json` is readable by group or other, the SDK warns once to `chmod 600` it (it holds a refresh token). The check is skipped on Windows, where confidentiality rests on the `%USERPROFILE%` ACL rather than mode bits. These warnings never raise and never change behavior.

## DPoP — sender-constrained tokens

For higher-security tenants, enable DPoP (RFC 9449):

```ruby
client = KnoxCall::Client.new(tenant: "acme", dpop: "always")
```

The SDK generates an ES256 keypair, binds the access token to it via the `cnf.jkt` claim, and signs a fresh proof JWT per request — token, management, and data-plane alike. Stolen tokens become useless without the keypair.

In the default `"auto"` mode the SDK starts with plain Bearer tokens and upgrades to DPoP automatically when the OAuth client record has `require_dpop` set (the token endpoint answers `invalid_dpop_proof`; the SDK generates a keypair, retries once, and operates as DPoP from then on). `dpop: "never"` opts out — if the server issues a DPoP-bound token anyway, the SDK raises `KnoxCall::TokenError` rather than 401-looping.

## Data plane

`client.call` proxies a request through a KnoxCall route to your upstream and returns the raw `Net::HTTPResponse` — the upstream's status belongs to you; the SDK never turns it into an error. Reference routes by **slug** — the write-once machine handle set on the route. Slugs are immutable (rename-proof, unlike names) and portable across tenants (unlike UUIDs). UUIDs also work; bare names are legacy.

```ruby
# GET
res = client.call("api-orders", path: "/users")

# POST with a body, targeting a specific environment
res = client.call("api-orders",
                  method: "POST",
                  path: "/v1/charges",
                  body: { amount: 2000, currency: "usd" },
                  environment: "staging")

res.code       # => "201"
res.body       # raw body string
```

`path` is the **upstream** path. On a KnoxCall cloud tenant host the data plane is served under `/api` (`https://{tenant}.knoxcall.com/api/<path>`); the SDK adds that prefix itself whenever the proxy base is a cloud tenant host with no path of its own, and uses any other base verbatim (self-hosted, or an override that already carries a path). So `/api/v2/tickets` reaches an upstream path that itself begins with `/api`.

A per-call `timeout:` overrides the client default.

### Bound routes

State the route (and optional defaults) once with `client.route`, then use plain HTTP verbs:

```ruby
printnode = client.route("api-printnode", environment: "production")

res = printnode.get("/computers")
res = printnode.post("/printjobs", body: job)
res = printnode.request("DELETE", "/printjobs/42")
# per-call options still override the bound defaults:
res = printnode.get("/computers", environment: "staging")
```

The handle holds no state beyond the defaults — retries, token refresh, and 401 re-mint behave exactly as on `call`.

### Ephemeral proxy

One-shot proxying without a pre-configured route — the proxy resolves `{{ token: "..." }}` expressions in flight:

```ruby
res = client.ephemeral("https://api.stripe.com/v1/charges", method: "POST", body: payload)
```

### Route-aware interception (preview)

Send an untouched third-party SDK's traffic through the Route that covers it —
and through the ephemeral proxy where no Route does — with no per-SDK wiring:

```ruby
knox = KnoxCall::Client.new(api_key: api_key)
stop = knox.wrap.intercept!(hosts: ["api.resend.com"])   # hosts with NO Route still covered (ephemeral)
stop.ready                                                # first manifest loaded

Net::HTTP.get(URI("https://api.hubapi.com/crm/v3/objects/contacts")) # any Net::HTTP caller, via the covering Route
stop.uninstall
```

Per request: the kill switch (`KNOXCALL_INTERCEPT=off`), KnoxCall's own hosts
and route-around rules go direct; a Route in the manifest covering host + path
goes through that Route (the Route injects the stored secret — no provider
credential travels); a host in `hosts:` with no Route goes through the
ephemeral proxy; everything else is untouched. Turn a Route's **Intercept**
toggle on and it takes effect on the next request after the 60 s TTL, or on
the next refusal, with no code change. Per-host options:
`hosts: { "api.resend.com" => { credential: { secret: "resend-key" } } }`
(escrow) or `{ unavailable: :direct }` (transit only: send direct when
KnoxCall is unreachable; the default is fail closed). `require_context: true`
limits interception to code inside `knox.wrap.routed { }`.

`intercept!` is **opt-in and experimental**: it prepends `Net::HTTP#request`,
which reaches Faraday's default adapter, `rest-client`, `httparty` and raw
Net::HTTP. Not reached: Typhoeus, Curb, `http.rb` (their own socket layer) —
point those SDKs at `gateway_url`. The same decisions are available without
the process-wide seam: `knox.wrap.faraday_connection(routes: :auto)` for an
SDK that takes an injected connection (controls on `conn.knoxcall`), and
`conn.builder.insert_before(Faraday::Adapter, *knox.wrap.faraday_middleware(hosts: [...]))`
for a stack the SDK builds itself.

This is a convenience, not a security boundary: it patches a process global
and composes with other Net::HTTP patchers (WebMock, APM agents) in install
order. Route mode is the custody path — the key never enters your process.

#### What the SDK reports about uncovered calls, and how to turn it off

**Reporting is on by default.** When the interceptor sends a call direct
because no Route covers its host and you did not list the host, and that call
carries a credential header (`Authorization`, `X-Api-Key`, or any name ending
in `-api-key`, `-token`, `-secret` or `-auth`), the SDK counts it. About once a
minute, the SDK reports the counts to KnoxCall
(`POST /v1/wrap/egress-observations`) with its own credential. The dashboard
uses the report to show which credentials still leave your process outside
KnoxCall custody.

**What is sent.** Each report carries the host, the first path segment, the
method, the credential header's **name**, a count, and first/last-seen times.
The header's **value** is never sent, and neither are the query string, the
body, or any deeper path.

**How to turn it off.** Pass `observe_uncovered: false` when you install, or set
`KNOXCALL_OBSERVE_UNCOVERED=off` in the environment. Nothing is reported while
`KNOXCALL_INTERCEPT=off`. If your key lacks `routes:read`, the first report is
refused, you get one warning, and reporting stops. `on_observation_flush:` receives the
server's `{accepted, dropped}` after each report.

## Pagination

The server wraps every JSON response in `{data, meta}` and paginates with `page`/`per_page` (default 20, cap 100). Single-object methods return the unwrapped Hash; paginated lists return the envelope; a few endpoints (environments, agents, crypto keys, PKI, dynamic-DB, OAuth clients, client credentials, route environments) return plain Arrays and take no page params.

```ruby
page = client.secrets.list(page: 2, per_page: 50)
page["data"]                  # => [...]
page["meta"]["total"]         # => 137
page["meta"]["total_pages"]   # => 3
page["meta"]["request_id"]    # for support

# Walk every page transparently — block form or lazy Enumerator:
client.secrets.each { |secret| puts secret["name"] }
names = client.secrets.each.map { |s| s["name"] }
first_ten = client.routes.each(per_page: 5).take(10) # fetches only 2 pages
```

`each` fetches page by page until `page >= meta.total_pages` (or an empty page). Sub-lists have `each_*` twins: `routes.each_log(id)`, `webhooks.each_log(id)`, `vaults.each_token(name)`.

## Resources

One-liner per area:

```ruby
# Routes
route = client.routes.create(name: "orders", target_base_url: "https://api.example.com")
logs  = client.routes.get_logs(route["id"])

# Route field-actions (declarative field-level encrypt/tokenize on the proxy path)
action = client.routes.create_action(route["id"], direction: "request", action: "tokenize",
                                                  selectors: ["$.card.number"], key_name: "cards-vault")

# Secrets
secret = client.secrets.create(name: "STRIPE_KEY", value: "sk_live_...")
client.secrets.set_value(secret["id"], value: "sk_live_rotated", environment: "production")

# OAuth2 provider secret (proxy injects the provider's access token upstream)
oauth = client.secrets.create_oauth2(name: "GITHUB", provider: "github",
                                     client_id: "cid", client_secret: "csec",
                                     scopes: ["repo"])
# Certificate / mTLS secret (certificate_type defaults to "pem")
cert  = client.secrets.create_certificate(name: "UPSTREAM_MTLS",
                                          certificate_content: pem, private_key: key)

# Webhooks (create returns the once-only "secret_key" — store it)
wh     = client.webhooks.create(name: "orders-hook", url: "https://hooks.example.com/knox",
                                event_types: ["request.error"])
types  = client.webhooks.list_event_types
result = client.webhooks.test(wh["id"])

# Clients (calling machines) + credentials
kc    = client.clients.create(name: "ci-runner", type: "server", ip_address: "203.0.113.9")
creds = client.clients.list_credentials(kc["id"])

# OAuth clients ("client_secret" shown once; "warning" carries the server's top-level warning)
oc = client.oauth_clients.create(name: "svc")

# Environments (bare array — no pagination)
envs = client.environments.list

# API keys (create returns the once-only plaintext "api_key")
key = client.api_keys.create(name: "deploy-bot")

# Account
acct  = client.account.get
usage = client.account.get_usage

# Audit logs
client.audit_logs.each(action: "secret.create") { |row| puts row["created_at"] }

# Agents ("agent_secret" shown once)
agent = client.agents.create("warehouse-agent")

# Crypto — keyed transit encryption
enc = client.crypto.encrypt("payments-key", plaintext: "hello")
dec = client.crypto.decrypt("payments-key", ciphertext: enc["ciphertext"], format: "utf8")

# Crypto — portable kc: encryption (structure-preserving, zero-config default key)
sealed = client.crypto.encrypt_data({ card: "4242..." })
opened = client.crypto.decrypt_data(sealed["ciphertext"])
meta   = client.crypto.inspect("kc:1:enc:...")
bundle = client.crypto.get_sealing_bundle          # public bits for browser-side sealing
cap    = client.crypto.mint_client_token(action: "decrypt", data: "kc:1:enc:...")

# PKI (cert + CRL are raw text, not JSON)
root = client.pki.create_root("internal", { common_name: "Acme Internal CA" })
pem  = client.pki.get_root_cert("internal")
leaf = client.pki.issue_cert("internal", "servers", common_name: "db.acme.internal")

# Vaults (tokenization)
vault = client.vaults.create(name: "cards-vault")
tok   = client.vaults.tokenize("cards-vault", value: "4242424242424242")
val   = client.vaults.detokenize("cards-vault", tok["token"])

# AI Gateway (secret -> gateway -> agent -> capability token).
# provider + upstream_secret_id compose the upstream route. An agent created
# with NEITHER those nor primary_route_id has no upstream and 502s on its first
# data-plane call. provider is a plain string — the catalog is server-side,
# and a bad value returns a 400 naming the valid set.
secret = client.secrets.create(name: "anthropic-key", value: ENV["ANTHROPIC_API_KEY"])
gw     = client.ai_gateway.create_gateway(name: "Prod", slug: "prod", budget_daily_usd: 50)
agent  = client.ai_gateway.create_agent(gw["id"], name: "copilot", slug: "copilot",
                                        provider: "anthropic", upstream_secret_id: secret["id"],
                                        default_model: "claude-sonnet-5")
minted = client.ai_gateway.mint_token(agent["id"], kind: "agent")
# minted["token"] is the plaintext capability token — shown exactly once.
# agent["agent_url"] is the base_url to point an AI SDK at.

# Dynamic DB credentials
minted = client.dynamic_db.mint("main-pg", "readonly")
leases = client.dynamic_db.list_leases

# Signup — credential-less, no client needed. Two steps: signup returns a claim
# handle and emails a sign-in link; claim_signup collects the key once clicked.
accepted = KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme Inc" })
claim = KnoxCall.claim_signup(accepted["claim_handle"])  # poll until status == "ready"
# claim["starter"]["api_key"]["api_key"] is shown exactly once — store it now.
```

## Wrapping third-party SDKs

Route an *official* third-party SDK's traffic through KnoxCall so its provider key leaves your codebase — the SDK keeps its own serialization, retries, idempotency keys, and error types; only its HTTP transport is swapped. Two halves:

**Escrow (all SDKs).** Hand the raw provider key to KnoxCall once; afterwards it is referenced by name and injected by the proxy.

```ruby
client.wrap.escrow(provider: "stripe", name: "stripe-live",
                   value: "sk_live_...", hosts: ["api.stripe.com"])
```

**Transport (Faraday-based SDKs only).** `wrap.faraday_connection` returns a `Faraday::Connection` whose transport re-targets each request through KnoxCall's ephemeral proxy in transparent mode — the Ruby analogue of the Node SDK's `wrap.fetch()`. Hand it to any SDK that accepts an **injected Faraday connection**.

```ruby
conn = client.wrap.faraday_connection(url: "https://api.example.com")
sdk  = SomeSDK.new(connection: conn)   # the SDK's own injection point
```

- **Transit mode (default)** lifts the wrapped SDK's own `Authorization` header out-of-band (never forwarded raw, never logged), with a both-must-agree Test/Live check against the client's `sandbox:` flag.
- **Escrow mode** (`credential: { secret: "stripe-live" }`) keeps the raw key in KnoxCall custody — only the escrowed name travels.
- **Route-around**: raw-card (PCI) endpoints are sent to the provider **directly**, untouched, by default; extend with `route_around:` and observe with `on_route_around:`.
- **Promoted routes**: after you promote wrapped traffic to a durable route, pass `route: "<slug>"`, or opt into `auto_switch: true` (surfaced via `on_promoted:`).

Requires the optional [`faraday`](https://rubygems.org/gems/faraday) gem — **KnoxCall itself has no runtime dependency on it** (`gem "faraday"` in your Gemfile); a clear `KnoxCall::Error` is raised if it is missing.

> **Limitation.** Ruby has **no production-safe *generic* transport seam** (intercepting `Net::HTTP` globally is monkey-patching, deliberately refused). So `faraday_connection` works **only** with SDKs that let you inject a Faraday connection. An SDK that builds its own connection internally, or exposes only a **base-URL override** (Resend, Mailgun, Airtable, …), cannot use it — mint a base-URL gateway with `wrap.gateway_url` instead:

```ruby
gw     = client.wrap.gateway_url(secret: "stripe-live", host: "api.stripe.com")
resend = Resend::Client.new(api_key: "placeholder", base_url: gw["base_url"])
```

## Webhook verification

`KnoxCall::Client.construct_event` (also available as `client.construct_event` and `client.webhooks.construct_event`) verifies the delivery's HMAC-SHA256 signature and parses it into an event Hash in one step. Pass the raw body string — never re-serialized JSON.

```ruby
post "/webhooks/knoxcall" do
  # Rack exposes inbound headers in request.env as HTTP_-prefixed CGI keys
  # (HTTP_X_WEBHOOK_SIGNATURE); construct_event wants real header names, so
  # strip the prefix and restore dashes.
  headers = request.env
                   .select { |k, _| k.start_with?("HTTP_") }
                   .transform_keys { |k| k.sub(/\AHTTP_/, "").tr("_", "-") }
  event = KnoxCall::Client.construct_event(request.body.read, headers, ENDPOINT_SECRET)

  case event["event"]
  when "audit.event"
    log.info "audit: #{event['data']['action']}"
  else # request.*
    log.info "#{event['data']['route_name']} -> #{event['data']['response']['status']}"
  end
  200
rescue KnoxCall::WebhookSignatureVerificationError
  halt 400, "bad signature"
end
```

Formats beyond the default `legacy` header (`stripe`, `github`, `slack`, `aws-sns`, `custom`) are selected with `format:`; the replay window defaults to 300s (`tolerance_seconds: nil` disables it); `custom` requires `header_name:`. All comparisons are constant-time. The boolean `verify_signature` helper remains for existing code.

## Errors

All API failures are typed subclasses of `KnoxCall::Error`:

```ruby
begin
  client.secrets.create(name: "orders", value: secret)
rescue KnoxCall::RateLimitError => e
  sleep e.retry_after || 1
rescue KnoxCall::ConflictError => e
  logger.warn "already exists: #{e.code}"        # 409 — do not blind-retry
rescue KnoxCall::ValidationError => e
  logger.warn "invalid: #{e.fields.inspect}"     # 422 — per-field breakdown when present
rescue KnoxCall::APIError => e
  logger.error "#{e.status_code} #{e.code}: #{e.message} (request #{e.request_id})"
end
```

Every `APIError` exposes `status_code`, `headers`, `body`, `code`/`type` (the server's
machine-readable error code) and `request_id` (the `X-Request-Id` correlation id, header
first then body) — branch on `e.code` rather than string-matching the message.

Hierarchy: `AuthenticationError` (401), `PermissionDeniedError` (403), `NotFoundError` (404), `ConflictError` (409), `ValidationError` (422, with `fields`), `RateLimitError` (429, with `retry_after`), `ServerError` (5xx), all under `APIError`; plus `SignupError` (with `status_code`/`error_type`/`request_id`), `WebhookSignatureVerificationError`, `TokenError`, and `NetworkError`/`ConnectionTimeoutError` for transport failures.

## Retries & idempotency

Management requests retry automatically on transport errors and HTTP 408/429/500/502/503/504 (never 409 — a real conflict does not resolve by replaying), with exponential half-jitter backoff and `Retry-After` honored up to 30s. Every mutating request carries a ULID `X-Idempotency-Key` that stays stable across retries, so replays are safe. A 401 purges the cached token and retries once with fresh credentials. Data-plane calls never replay a mutating request after it may have reached the wire. Tune with `retry_max_attempts:`, `retry_base_delay:`, `retry_max_delay:`.
