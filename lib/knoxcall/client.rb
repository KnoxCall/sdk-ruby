require "net/http"
require "uri"
require "json"
require "openssl"
require "time"
require "date"

module KnoxCall
  # KnoxCall API client.
  #
  #   client = KnoxCall::Client.new(tenant: "acme", access_token: "kc_live_...")
  #   routes = client.routes.list
  #   res    = client.call("route-uuid", path: "/v1/orders")
  #
  # Credentials can be passed flat (access_token:/api_key: or
  # client_id: + client_secret:), as a bootstrap: object, or resolved from
  # KNOXCALL_* environment variables — `KnoxCall::Client.new` works zero-arg
  # when KNOXCALL_TENANT plus a credential are set in the environment.
  # Zero-arg resolution order (PARITY §2): KNOXCALL_ACCESS_TOKEN /
  # KNOXCALL_API_KEY → the `knoxcall login` credentials file
  # (~/.knoxcall/credentials.json) → KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET.
  #
  # The client is Mutex-safe: a single instance can be shared across Puma /
  # Sidekiq threads. The token cache is single-flight — concurrent callers
  # block on one token request instead of stampeding the token endpoint.
  class Client
    RETRYABLE_STATUSES = [408, 429, 500, 502, 503, 504].freeze # NOT 409 — a real conflict does not resolve by replaying

    # The value +request+ returns for a 304 Not Modified when the caller opted
    # in with +allow_not_modified:+ (a conditional GET carrying If-None-Match).
    # Internal: the one consumer is +wrap.intercept_manifest(if_none_match:)+,
    # which maps it to nil. Without the opt-in a 304 keeps its old shape (an
    # empty body read as nil), so nothing else changes.
    NOT_MODIFIED = Object.new
    def NOT_MODIFIED.inspect = "KnoxCall::Client::NOT_MODIFIED"
    NOT_MODIFIED.freeze
    # The dated API version this SDK is built against. Sent as the
    # `KnoxCall-Version` header on every management request so the SDK stays
    # pinned to a known API shape even after the server ships a newer default
    # (see the server's src/client-api/versioning.ts). Must be a version the
    # server's registry knows, or requests are rejected 400.
    DEFAULT_API_VERSION = "2026-08-05"
    # Honor a server Retry-After up to this long; beyond it, fail fast so
    # callers can apply their own scheduling instead of blocking a worker.
    RETRY_AFTER_CAP_SECONDS = 30.0
    REFRESH_AHEAD_SECONDS = 300.0
    # A cached token inside the refresh-ahead window is still usable this
    # long before real expiry; used when the token endpoint is down.
    STALE_TOKEN_MIN_REMAINING_SECONDS = 10.0

    METHOD_CLASSES = {
      "GET" => Net::HTTP::Get,
      "HEAD" => Net::HTTP::Head,
      "POST" => Net::HTTP::Post,
      "PUT" => Net::HTTP::Put,
      "PATCH" => Net::HTTP::Patch,
      "DELETE" => Net::HTTP::Delete,
      "OPTIONS" => Net::HTTP::Options
    }.freeze

    # Transport failures where the connection was never established — the
    # request never left the machine, so a retry is safe for any method.
    CONNECT_ERRORS = [Errno::ECONNREFUSED, Net::OpenTimeout, SocketError].freeze

    # Management hosts whose data plane lives on a per-tenant subdomain —
    # sandbox hosts use the sandbox- prefixed shape (node core.ts is the
    # reference; any other host is self-hosted and proxies on itself).
    SANDBOX_PROXY_HOSTS = %w[sandbox.knoxcall.com sandbox-staging.knoxcall.com].freeze
    PLAIN_PROXY_HOSTS = %w[api.knoxcall.com api-staging.knoxcall.com].freeze
    # The labels under knoxcall.com that are NOT a tenant's data-plane host
    # (management + marketing); see .data_plane_path_prefix.
    NON_TENANT_LABELS = %w[api sandbox api-staging sandbox-staging www staging admin].freeze
    CLOUD_TENANT_HOST_RE = /\A([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.knoxcall\.com\z/

    # Where the data plane lives under a proxy base (PARITY §5).
    #
    # On a KnoxCall CLOUD tenant host the proxy is served ONLY under +/api+
    # (+https://{slug}.knoxcall.com/api/<upstream path>+: server.ts strips the
    # prefix, and every other path on that host is the dashboard). +call+
    # therefore places the upstream path under +/api+ whenever the base names
    # such a host and carries no path of its own — the derived plain/sandbox
    # shapes and an explicit override alike, any port. Every other base is used
    # verbatim: self-hosted mounts the proxy at +/+, and a base that already
    # carries a path IS the entry point (the agent bundle spells the same base
    # as +…knoxcall.com/api+). Until 2026-09-25 nothing added the prefix, so the
    # documented +path: "/users"+ answered the dashboard HTML on every tenant
    # host; the live smokes hid it by hard-coding +path: "/api/get"+.
    def self.data_plane_path_prefix(proxy_base_url)
      uri = URI.parse(proxy_base_url.to_s)
      return "" unless uri.path.nil? || uri.path.empty? || uri.path == "/"

      m = CLOUD_TENANT_HOST_RE.match(uri.host.to_s.downcase)
      return "" if m.nil? || NON_TENANT_LABELS.include?(m[1])

      "/api"
    rescue URI::InvalidURIError
      ""
    end

    # A tenant slug becomes a data-plane hostname (https://<slug>.knoxcall.com),
    # so before it is interpolated into a host it MUST be a bare DNS label — a
    # hostile slug adopted from a token response, /v1/account, or the
    # credentials file (e.g. "evil.com#") would otherwise misdirect the tenant's
    # bearer token to an attacker-controlled host (PARITY §2). Anchored with
    # \A..\z (never ^..$) so a value embedding a newline can't satisfy a
    # line-anchored match; case-insensitive to mirror node core.ts.
    TENANT_SLUG_RE = /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/i

    CONSTRUCT_EVENT_FORMATS = %w[legacy stripe github slack aws-sns custom].freeze

    # Auth-bearing headers the proxy data plane consumes to identify the caller
    # (PARITY §5). The SDK's own credential is the SOLE authority on the data
    # plane, so any caller-supplied copy of these is stripped from
    # call()/ephemeral() headers before the SDK sets its own — otherwise an
    # integrator forwarding untrusted end-user headers could inject an alternate
    # proxy identity (x-knoxcall-agent-*) or, on the legacy-key path, a Bearer
    # Authorization the proxy would honor over the SDK's own x-knoxcall-key.
    PROXY_AUTH_HEADERS = %w[
      authorization dpop x-knoxcall-key x-knoxcall-agent-id x-knoxcall-agent-token
    ].freeze

    # Markers the SDK owns on the data plane (PARITY §21.2). Not auth — the
    # server treats them as informational — but a caller-supplied copy is
    # stripped the same way, so an app cannot relabel its own calls as
    # interceptor traffic through the headers Hash. The interceptors set the
    # marker through +call(..., _origin: SDK_INTERCEPT_ORIGIN)+, never headers.
    SDK_MARKER_HEADERS = %w[x-knoxcall-origin].freeze

    # The one value +call+'s internal +_origin:+ accepts: the route-aware
    # interceptors' reroute marker, sent as +x-knoxcall-origin: sdk-intercept+
    # so the API Log can show which Route calls the SDK rerouted from a
    # third-party SDK and which were direct. Internal — nothing public sets it.
    SDK_INTERCEPT_ORIGIN = "sdk-intercept"

    # The management base URL, the data-plane base URL (nil until the tenant
    # is discovered) and the default environment — read by the route-aware
    # wrap pipeline (own-host refusal; the manifest's environment).
    attr_reader :base_url, :proxy_base_url, :environment
    attr_reader :tenant, :api_version, :sandbox, :routes, :secrets, :webhooks, :workflows, :clients, :oauth_clients,
                :environments, :api_keys, :roles, :account, :audit_logs, :logs, :agents,
                :crypto, :pki, :vaults, :dynamic_db, :ai_gateway, :wrap, :opportunities

    def initialize(opts = {})
      # Tenant is optional: when absent it is discovered from the first token
      # response (or /v1/account for pre-acquired tokens). Only the data-plane
      # hostname needs it client-side; management calls resolve the tenant
      # server-side from the credential.
      @tenant = opts[:tenant] || ENV["KNOXCALL_TENANT"]
      @tenant = nil if @tenant && @tenant.empty?
      # Default environment for data-plane calls; per-call and bound-route
      # values win, and nil means the server picks the tenant default.
      @environment = opts[:environment] || ENV["KNOXCALL_ENVIRONMENT"]

      # Mutual exclusion is enforced on the EXPLICITLY passed options before
      # any env fill, so a stray environment variable never masks a caller
      # mistake — and env fill is skipped entirely once anything explicit
      # (flat or bootstrap:) was passed.
      explicit = {
        client_id: opts[:client_id],
        client_secret: opts[:client_secret],
        access_token: opts[:access_token],
        api_key: opts[:api_key]
      }.compact
      if opts[:bootstrap] && !explicit.empty?
        raise ArgumentError, "bootstrap: cannot be combined with #{explicit.keys.join(', ')}"
      end
      if explicit.key?(:access_token) && explicit.key?(:api_key)
        raise ArgumentError,
              "pass either access_token or api_key, not both (they are two spellings of the same credential)"
      end
      token = explicit[:access_token] || explicit[:api_key]
      if token && (explicit.key?(:client_id) || explicit.key?(:client_secret))
        raise ArgumentError, "a token credential cannot be combined with client_id/client_secret"
      end
      if explicit.key?(:client_id) != explicit.key?(:client_secret)
        raise ArgumentError, "client_id and client_secret must be provided together"
      end

      @bootstrap = opts[:bootstrap]
      if @bootstrap || !explicit.empty?
        @api_key       = token
        @client_id     = explicit[:client_id]
        @client_secret = explicit[:client_secret]
      else
        # Two spellings, one behavior; KNOXCALL_ACCESS_TOKEN wins when both are set.
        @api_key = ENV["KNOXCALL_ACCESS_TOKEN"] || ENV["KNOXCALL_API_KEY"]
        if @api_key.nil? && CredentialsFile.available?
          # Chain slot 2 (PARITY §2): the credentials file written by
          # `knoxcall login`. Ruby has no cloud auto-detect, so zero-arg
          # resolution is: env access token → credentials file → env
          # client-credentials — a file check only, no network I/O. Present =
          # file exists AND the selected profile parses; anything
          # missing/malformed skips the provider silently.
          @bootstrap = StoredCredentials.new
        end
        unless @bootstrap
          @client_id     = ENV["KNOXCALL_CLIENT_ID"]
          @client_secret = ENV["KNOXCALL_CLIENT_SECRET"]
        end
      end

      @timeout = opts[:timeout] || 30

      @retry_max_attempts = opts[:retry_max_attempts] || 3
      @retry_base_delay   = opts[:retry_base_delay]   || 0.1
      @retry_max_delay    = opts[:retry_max_delay]    || 5.0

      # DPoP (RFC 9449, PARITY §7): "auto" starts Bearer and upgrades when
      # the oauth client requires proofs; "always" generates the keypair up
      # front; "never" opts out (a DPoP-bound token then raises).
      @dpop_mode = (opts[:dpop] || "auto").to_s
      unless %w[auto always never].include?(@dpop_mode)
        raise ArgumentError,
              %(invalid dpop mode #{opts[:dpop].inspect} — expected "auto", "always", or "never")
      end
      @dpop_key = @dpop_mode == "always" ? DpopKeyPair.generate : nil
      # Hook for JSON-encoding caller-specific objects (called for values
      # JSON.generate can't represent natively; must return an encodable value).
      @json_encoder = opts[:json_encoder]

      # Dated API version pinned on every management request via the
      # `KnoxCall-Version` header; caller may override, else DEFAULT_API_VERSION.
      @api_version = opts[:api_version] || DEFAULT_API_VERSION

      # Sandbox / Test mode (Stripe-style isolated environment): defaults the
      # management base to https://sandbox.knoxcall.com and the data plane to
      # https://sandbox-{tenant}.knoxcall.com. Requires a tk_test_… API key.
      # An explicit base_url (or the base-URL env vars) wins over the sandbox
      # default — mirrors node core.ts.
      sandbox = opts[:sandbox] == true
      # Exposed via attr_reader :sandbox — the wrap Faraday transport reads it
      # for the both-must-agree Test/Live key check (PARITY §18). Always a
      # boolean, never nil.
      @sandbox = sandbox
      default_base = sandbox ? "https://sandbox.#{DEFAULT_CLOUD_HOST}" : DEFAULT_API_BASE
      # KNOXCALL_BASE_URL is canonical; KNOXCALL_API_BASE_URL is the legacy
      # spelling and loses when both are set.
      @base_url = (opts[:base_url] || ENV["KNOXCALL_BASE_URL"] ||
                   ENV["KNOXCALL_API_BASE_URL"] || default_base).chomp("/")

      # The credentials file's tenant/base_url seed the client only when the
      # caller didn't set them explicitly — constructor options, env vars,
      # and sandbox: always win. Seeding runs before the proxy-host
      # derivation below, so the data plane follows the seeded values.
      if @bootstrap.is_a?(StoredCredentials)
        base_url_explicit = !!(opts[:base_url] || ENV["KNOXCALL_BASE_URL"] ||
                               ENV["KNOXCALL_API_BASE_URL"] || sandbox)
        seed_from_stored_credentials(@bootstrap, base_url_explicit: base_url_explicit)
      end

      base_host = begin
        URI.parse(@base_url).host.to_s.downcase
      rescue URI::InvalidURIError
        ""
      end
      # Subdomain shape to derive once the tenant is known (:plain/:sandbox).
      @proxy_shape = nil
      # nil proxy_base_url = derive lazily once the tenant is discovered.
      @proxy_base_url =
        if opts[:proxy_base_url]
          opts[:proxy_base_url].chomp("/")
        elsif (p = ENV["KNOXCALL_PROXY_BASE_URL"])
          p.chomp("/")
        elsif SANDBOX_PROXY_HOSTS.include?(base_host)
          # Sandbox hosts: the per-tenant proxy lives on the sandbox-
          # prefixed subdomain. Validate the slug before it becomes a host.
          @proxy_shape = :sandbox
          @tenant ? "https://sandbox-#{assert_tenant_slug(@tenant)}.#{DEFAULT_CLOUD_HOST}" : nil
        elsif PLAIN_PROXY_HOSTS.include?(base_host)
          @proxy_shape = :plain
          @tenant ? "https://#{assert_tenant_slug(@tenant)}.#{DEFAULT_CLOUD_HOST}" : nil
        else
          # Local dev / self-hosted: the proxy runs on the same host, so no
          # tenant is needed.
          @base_url
        end

      # Plaintext http:// to a non-loopback host sends credentials and tokens
      # in the clear — warn once (never block: http://localhost is the normal
      # dev case). Both the management base and the resolved data plane are
      # checked. @proxy_base_url may still be nil here (derived lazily once the
      # tenant is discovered), but any lazy derivation yields an https:// cloud
      # host, so there is nothing plaintext left unchecked.
      if Warnings.insecure_remote_url?(@base_url)
        Warnings.warn_once(
          "KNOXCALL_INSECURE_BASE_URL",
          "KnoxCall base URL #{@base_url} uses plaintext http:// to a non-loopback host — " \
          "credentials and access tokens will be sent unencrypted. Use https:// " \
          "(plain http:// is only safe for localhost)."
        )
      end
      if Warnings.insecure_remote_url?(@proxy_base_url)
        Warnings.warn_once(
          "KNOXCALL_INSECURE_PROXY_URL",
          "KnoxCall proxy base URL #{@proxy_base_url} uses plaintext http:// to a non-loopback host — " \
          "proxied requests and the SDK credential will be sent unencrypted. Use https:// " \
          "(plain http:// is only safe for localhost)."
        )
      end

      @token_cache = nil
      @token_mutex = Mutex.new
      @discovery_mutex = Mutex.new

      @routes       = Resources::Routes.new(self)
      @secrets      = Resources::Secrets.new(self)
      @webhooks     = Resources::Webhooks.new(self)
      @workflows    = Resources::Workflows.new(self)
      @clients      = Resources::Clients.new(self)
      @oauth_clients = Resources::OAuthClients.new(self)
      @environments = Resources::Environments.new(self)
      @api_keys     = Resources::ApiKeys.new(self)
      @roles        = Resources::Roles.new(self)
      @account      = Resources::Account.new(self)
      @audit_logs   = Resources::AuditLogs.new(self)
      # Per-call proxy request log + Merkle inclusion proofs. Not the change
      # log — that is +audit_logs+.
      @logs         = Resources::Logs.new(self)
      @agents       = Resources::Agents.new(self)
      @crypto       = Resources::Crypto.new(self)
      @pki          = Resources::Pki.new(self)
      @vaults       = Resources::Vaults.new(self)
      @dynamic_db   = Resources::DynamicDb.new(self)
      @ai_gateway   = Resources::AiGateway.new(self)
      @wrap         = Resources::Wrap.new(self)
      @opportunities = Resources::Opportunities.new(self)
    end

    # Never dump credentials or the cached token when the client is inspected
    # (consoles, loggers, exception trackers capturing locals).
    def inspect
      "#<KnoxCall::Client tenant=#{@tenant.inspect} base_url=#{@base_url.inspect}>"
    end

    # -- Token management -------------------------------------------------------

    def token
      @token_mutex.synchronize do
        cached = @token_cache
        return adopt_tenant(cached) if cached && token_fresh?(cached)
        begin
          adopt_tenant(@token_cache = fetch_token)
        rescue Error
          # Token endpoint unreachable or erroring during the refresh-ahead
          # window: a cached token that hasn't actually expired is still
          # good — use it rather than failing the caller's request.
          raise unless cached && cached[:expires_at] - Time.now > STALE_TOKEN_MIN_REMAINING_SECONDS
          adopt_tenant(cached)
        end
      end
    end

    def purge_token
      @token_mutex.synchronize { @token_cache = nil }
    end

    # Learn the tenant from a token response when constructed without one.
    # Called with @token_mutex held.
    def adopt_tenant(cached)
      @tenant ||= cached[:tenant] if cached[:tenant]
      cached
    end

    # Resolve the data-plane base URL, discovering the tenant if needed: the
    # token response carries the slug; pre-acquired tokens (and older servers)
    # fall back to one GET /v1/account. @discovery_mutex guarantees the
    # discovery runs at most once even under concurrent first calls.
    def ensure_proxy_base_url
      return @proxy_base_url if @proxy_base_url

      @discovery_mutex.synchronize do
        return @proxy_base_url if @proxy_base_url # discovered while we waited

        token if @tenant.nil? # may adopt the tenant from the token response
        if @tenant.nil?
          account = request("GET", "/v1/account")
          slug = account.is_a?(Hash) ? account.dig("data", "slug") : nil
          unless slug.is_a?(String) && !slug.empty?
            raise Error,
                  "could not discover the tenant from the credential — " \
                  "pass tenant: ... or set the KNOXCALL_TENANT environment variable"
          end
          @tenant = slug
        end
        @proxy_base_url =
          if @proxy_shape == :sandbox
            "https://sandbox-#{assert_tenant_slug(@tenant)}.#{DEFAULT_CLOUD_HOST}"
          else
            "https://#{assert_tenant_slug(@tenant)}.#{DEFAULT_CLOUD_HOST}"
          end
      end
    end

    # -- HTTP core --------------------------------------------------------------

    # Management API request: typed errors on HTTP failure, retries on
    # 408/429/5xx with half-jitter backoff, one transparent re-auth on 401,
    # and a per-logical-request idempotency key on mutating methods.
    #
    # With +allow_not_modified: true+ a 304 Not Modified is a success with no
    # body and returns +NOT_MODIFIED+ instead of reading the empty body; auth,
    # the one transparent re-auth on 401 and the retry policy are unchanged,
    # and +headers+ (the If-None-Match) ride on every attempt.
    def request(method, path, query: nil, body: nil, headers: nil, allow_not_modified: false)
      method = method.to_s.upcase
      idem_key = ULID.generate unless %w[GET HEAD].include?(method)

      reauth_done = false
      attempt = 0
      loop do
        attempt += 1
        begin
          tok = token
          uri = URI.parse(@base_url + normalize_path(path))
          uri.query = URI.encode_www_form(query.compact) if query && !query.empty?

          req = build_request(method, uri)
          (headers || {}).each { |k, v| req[k] = v }
          req["Accept"] ||= "application/json"
          # Pin the API version so a newer server default can't silently change
          # the response shape under us; a caller-set header still wins.
          req["KnoxCall-Version"] ||= @api_version
          req["X-Idempotency-Key"] = idem_key if idem_key
          # SDK-set Authorization always wins (Net::HTTP headers are
          # case-insensitive); caller-set Content-Type is respected.
          req["Authorization"] = "#{tok[:token_type]} #{tok[:access_token]}"
          req["DPoP"] = dpop_proof(method, uri.to_s, tok[:access_token]) if tok[:token_type] == "DPoP"
          encode_body(body, req)

          resp = perform(uri, req)
          # A conditional GET the server answered "unchanged": success, no body.
          return NOT_MODIFIED if allow_not_modified && resp.code.to_i == 304
          return handle_response(resp)
        rescue AuthenticationError
          # One transparent re-auth: purge the cached token so the immediate
          # retry runs with freshly minted credentials.
          purge_token
          raise if reauth_done || attempt >= @retry_max_attempts
          reauth_done = true
        rescue APIError => e
          raise unless attempt < @retry_max_attempts && RETRYABLE_STATUSES.include?(e.status_code)
          sleep retry_delay(e, attempt)
        rescue ConnectionTimeoutError, Net::OpenTimeout, Net::ReadTimeout => e
          raise as_sdk_error(e) unless attempt < @retry_max_attempts
          sleep backoff_delay(attempt)
        rescue NetworkError, OpenSSL::SSL::SSLError, EOFError, SocketError, SystemCallError, IOError => e
          raise as_sdk_error(e) unless attempt < @retry_max_attempts
          sleep backoff_delay(attempt)
        end
      end
    end

    # -- Proxy helpers ----------------------------------------------------------

    # Make a proxied request through a KnoxCall route.
    # Pass the route UUID (preferred) or name.
    #
    # Returns the raw Net::HTTPResponse — the proxied upstream's status
    # belongs to the caller and is never raised. Transport failures map to
    # NetworkError / ConnectionTimeoutError and are retried only when safe;
    # a rejected token is purged and re-minted once. `timeout:` overrides the
    # client timeout for this call.
    #
    # +_origin:+ is internal: the route-aware interceptors pass
    # +SDK_INTERCEPT_ORIGIN+ so the request carries
    # +x-knoxcall-origin: sdk-intercept+ (PARITY §21.2). A direct call sends
    # nothing — absence IS "direct" on the server.
    def call(route, method: "GET", path: "/", body: nil, headers: {}, environment: nil, query: nil, timeout: nil,
             _origin: nil)
      sdk_headers = { "x-knoxcall-route" => route }
      environment ||= @environment
      sdk_headers["x-knoxcall-environment"] = environment if environment
      unless _origin.nil?
        unless _origin == SDK_INTERCEPT_ORIGIN
          raise ArgumentError, "unknown call origin #{_origin.inspect}; the only marker is #{SDK_INTERCEPT_ORIGIN.inspect}"
        end

        sdk_headers["x-knoxcall-origin"] = SDK_INTERCEPT_ORIGIN
      end

      # +path+ is the UPSTREAM path; the entry point is the SDK's to add (PARITY §5).
      base = ensure_proxy_base_url
      proxy_send(method, base + Client.data_plane_path_prefix(base) + normalize_path(path),
                 headers: headers, sdk_headers: sdk_headers,
                 query: query, body: body, timeout: timeout,
                 legacy_key_as_header: true)
    end

    # Bind a route (and optional call defaults) once, then make plain
    # HTTP-verb calls against it:
    #
    #   printnode = client.route("3f1e2c9a-...", environment: "production")
    #   computers = JSON.parse(printnode.get("/computers").body)
    #   printnode.post("/printjobs", body: payload)
    def route(route, environment: nil, headers: {}, timeout: nil)
      BoundRoute.new(self, route, environment: environment, headers: headers, timeout: timeout)
    end

    # Make a one-shot proxied request via the Ephemeral Proxy.
    def ephemeral(upstream_url, method: "GET", body: nil, headers: {}, encrypted: nil, timeout_ms: nil, timeout: nil,
                  mode: nil, upstream_authorization: nil, upstream_auth_secret: nil, upstream_auth_scheme: nil)
      sdk_headers = { "X-Knox-Proxy-URL" => upstream_url }
      sdk_headers["X-Knox-Encrypted"] = encrypted if encrypted
      sdk_headers["X-Knox-Timeout-Ms"] = timeout_ms.to_s if timeout_ms
      sdk_headers["X-Knox-Proxy-Mode"] = "transparent" if mode == "transparent"
      sdk_headers["X-Knox-Upstream-Authorization"] = upstream_authorization unless upstream_authorization.nil?
      sdk_headers["X-Knox-Upstream-Auth-Secret"] = upstream_auth_secret unless upstream_auth_secret.nil?
      sdk_headers["X-Knox-Upstream-Auth-Scheme"] = upstream_auth_scheme unless upstream_auth_scheme.nil?

      proxy_send(method, @base_url + "/v1/proxy",
                 headers: headers, sdk_headers: sdk_headers,
                 body: body, timeout: timeout)
    end

    # Verify a KnoxCall webhook HMAC-SHA256 signature.
    def self.verify_signature(raw_body, signature, secret, tolerance_seconds: 300, timestamp: nil)
      parts = {}
      signature.split(",").each do |part|
        part = part.strip
        parts[:t]  = part[2..] if part.start_with?("t=")
        parts[:v1] = part[3..] if part.start_with?("v1=")
      end

      return false unless parts[:t] && parts[:v1]

      if tolerance_seconds > 0 && timestamp
        return false if (timestamp - parts[:t].to_i).abs > tolerance_seconds
      end

      expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{parts[:t]}.#{raw_body}")
      OpenSSL::HMAC.hexdigest("SHA256", secret, parts[:v1]) == OpenSSL::HMAC.hexdigest("SHA256", secret, expected)
    end

    def verify_signature(...) = self.class.verify_signature(...)

    # Verify an incoming webhook delivery AND parse it in one step.
    #
    # Pass the RAW request body (never re-serialized JSON), the request
    # headers (looked up case-insensitively), and the endpoint secret. On
    # success returns the delivery envelope as a Hash with string keys:
    #
    #   {
    #     "event"        => String,   # e.g. "request.success", "audit.event" —
    #                                 # open list, unknown types parse fine
    #     "timestamp"    => String,   # ISO-8601
    #     "webhook_id"   => String,   # present on request.* events
    #     "webhook_name" => String,   # present on request.* events
    #     "data"         => Hash      # request.*: {"route_id", "route_name",
    #                                 #   "environment", "request" => {"method", "path", "ip"},
    #                                 #   "response" => {"status", "latency_ms"}}
    #                                 # audit.event: {"id", "action", "resource_type",
    #                                 #   "resource_id", "details", "ip_address"}
    #   }
    #
    # Also available as +client.construct_event+ and
    # +client.webhooks.construct_event+.
    #
    # @param raw_body [String] the raw request body bytes
    # @param headers [Hash] request headers, any casing (values may be arrays)
    # @param secret [String] the webhook's endpoint secret
    # @param format [String] one of legacy|stripe|github|slack|aws-sns|custom
    #   (default "legacy") — must match the webhook's configured hmac_format
    # @param tolerance_seconds [Integer, nil] replay window, default 300. For
    #   stripe/slack the check runs against the signed header timestamp; for
    #   the other formats against the envelope's "timestamp" field. Pass nil
    #   (or 0) to disable all timestamp checks.
    # @param header_name [String, nil] required when format is "custom",
    #   ignored otherwise
    # @return [Hash] the parsed delivery envelope
    # @raise [WebhookSignatureVerificationError] on ANY verification failure
    #   (missing header, signature mismatch, stale timestamp, body not a JSON
    #   object) — never returns a partial event, and the message never echoes
    #   the signature or secret
    # @raise [ArgumentError] on option misuse (unknown format, missing
    #   header_name for "custom")
    def self.construct_event(raw_body, headers, secret, format: "legacy", tolerance_seconds: 300, header_name: nil)
      unless CONSTRUCT_EVENT_FORMATS.include?(format)
        raise ArgumentError, "format must be one of #{CONSTRUCT_EVENT_FORMATS.join(', ')}"
      end
      # Explicit nil/0 disables replay protection entirely (documented).
      tolerance = tolerance_seconds && tolerance_seconds.to_i.positive? ? tolerance_seconds.to_i : nil
      now = Time.now.to_i

      # Case-insensitive header lookup; multi-value headers use the first value.
      lower = {}
      (headers || {}).each do |name, value|
        lower[name.to_s.downcase] = (value.is_a?(Array) ? value.first : value).to_s
      end
      fetch_header = lambda do |name|
        value = lower[name.downcase]
        if value.nil? || value.strip.empty?
          raise WebhookSignatureVerificationError, "missing signature header #{name}"
        end
        value.strip
      end
      # hex signatures arrive as `<prefix><hex>` (e.g. sha256=…, v0=…); the
      # prefix is shape, not signature — strip it when present.
      strip_prefix = ->(value, prefix) { value.start_with?(prefix) ? value[prefix.length..] : value }

      case format
      when "legacy", "github", "custom"
        signature_header =
          case format
          when "legacy" then "X-Webhook-Signature"
          when "github" then "X-Hub-Signature-256"
          else
            header_name or raise ArgumentError, "header_name is required when format is \"custom\""
          end
        signature = strip_prefix.call(fetch_header.call(signature_header), "sha256=")
        expected = OpenSSL::HMAC.hexdigest("SHA256", secret, raw_body)
        unless OpenSSL.secure_compare(expected, signature)
          raise WebhookSignatureVerificationError, "signature mismatch (#{format} format)"
        end
      when "aws-sns"
        signature = fetch_header.call("x-amz-sns-signature")
        expected = [OpenSSL::HMAC.digest("SHA256", secret, raw_body)].pack("m0")
        unless OpenSSL.secure_compare(expected, signature)
          raise WebhookSignatureVerificationError, "signature mismatch (aws-sns format)"
        end
      when "stripe"
        # `t=<ts>,v1=<hex>` — multiple comma-separated pairs allowed; any
        # matching v1 passes (mirrors Stripe's own secret rotation).
        ts = nil
        candidates = []
        fetch_header.call("Stripe-Signature").split(",").each do |part|
          part = part.strip
          ts = part[2..] if part.start_with?("t=")
          candidates << part[3..] if part.start_with?("v1=")
        end
        unless ts&.match?(/\A\d+\z/) && !candidates.empty?
          raise WebhookSignatureVerificationError, "malformed Stripe-Signature header"
        end
        if tolerance && (now - ts.to_i).abs > tolerance
          raise WebhookSignatureVerificationError, "timestamp outside tolerance (stripe format)"
        end
        expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{ts}.#{raw_body}")
        matched = false
        candidates.each do |candidate|
          # no early break — check every candidate, constant-time each
          matched = true if OpenSSL.secure_compare(expected, candidate)
        end
        raise WebhookSignatureVerificationError, "signature mismatch (stripe format)" unless matched
      when "slack"
        ts = fetch_header.call("X-Slack-Request-Timestamp")
        unless ts.match?(/\A\d+\z/)
          raise WebhookSignatureVerificationError, "malformed X-Slack-Request-Timestamp header"
        end
        if tolerance && (now - ts.to_i).abs > tolerance
          raise WebhookSignatureVerificationError, "timestamp outside tolerance (slack format)"
        end
        signature = strip_prefix.call(fetch_header.call("X-Slack-Signature"), "v0=")
        expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "v0:#{ts}:#{raw_body}")
        unless OpenSSL.secure_compare(expected, signature)
          raise WebhookSignatureVerificationError, "signature mismatch (slack format)"
        end
      end

      event = begin
        JSON.parse(raw_body)
      rescue JSON::ParserError
        nil
      end
      raise WebhookSignatureVerificationError, "delivery body is not a JSON object" unless event.is_a?(Hash)

      # Formats without a signed timestamp: enforce the replay window against
      # the envelope's own ISO-8601 timestamp field.
      if tolerance && %w[legacy github aws-sns custom].include?(format)
        envelope_ts = begin
          event["timestamp"].is_a?(String) ? Time.iso8601(event["timestamp"]).to_i : nil
        rescue ArgumentError
          nil
        end
        if envelope_ts.nil?
          raise WebhookSignatureVerificationError,
                "delivery timestamp missing or invalid (pass tolerance_seconds: nil to skip replay checks)"
        end
        if (now - envelope_ts).abs > tolerance
          raise WebhookSignatureVerificationError, "timestamp outside tolerance (#{format} format)"
        end
      end

      event
    end

    def construct_event(...) = self.class.construct_event(...)

    private

    # Shared data-plane sender for call()/ephemeral(). Proxied responses are
    # returned raw, but transport failures are mapped to SDK error classes
    # and retried when safe, and a 401 triggers one token purge + re-mint so
    # a revoked token can't wedge a long-lived client.
    def proxy_send(method, url, headers:, sdk_headers:, query: nil, body: nil, timeout: nil, legacy_key_as_header: false)
      method = method.to_s.upcase
      reauth_done = false
      attempt = 0
      loop do
        attempt += 1
        tok = token

        uri = URI.parse(url)
        uri.query = URI.encode_www_form(query.compact) if query && !query.empty?

        req = build_request(method, uri)
        (headers || {}).each { |k, v| req[k] = v }
        # The SDK credential is the sole data-plane auth authority (PARITY §5):
        # drop any caller-supplied proxy-auth headers before we set our own, so
        # an integrator forwarding untrusted end-user headers can never inject
        # an alternate proxy identity (x-knoxcall-agent-*) or, on the
        # legacy-key path, a Bearer Authorization the proxy would honor over our
        # x-knoxcall-key. Net::HTTP header deletion is case-insensitive, so any
        # casing the caller used is covered.
        PROXY_AUTH_HEADERS.each { |h| req.delete(h) }
        SDK_MARKER_HEADERS.each { |h| req.delete(h) }
        # Explicit keyword arguments always win over the headers dict,
        # and SDK-set auth headers always win.
        sdk_headers.each { |k, v| req[k] = v }
        # legacy_key_as_header is set on call() requests: the route proxy's
        # OAuth detection matches the kc_ token prefix only, so a legacy
        # tk_/AKE credential must travel as x-knoxcall-key (Bearer would
        # fall through to the legacy path and 401). ephemeral() targets
        # /v1/proxy, whose auth accepts any credential format as Bearer.
        if legacy_key_as_header && tok[:token_type] == "Bearer" && !tok[:access_token].start_with?("kc_")
          req["x-knoxcall-key"] = tok[:access_token]
        else
          req["Authorization"] = "#{tok[:token_type]} #{tok[:access_token]}"
          req["DPoP"] = dpop_proof(method, uri.to_s, tok[:access_token]) if tok[:token_type] == "DPoP"
        end
        encode_body(body, req)

        begin
          resp = perform(uri, req, timeout: timeout)
        rescue *CONNECT_ERRORS => e
          # Never reached the wire — safe to retry, even for mutating methods.
          raise as_sdk_error(e) unless attempt < @retry_max_attempts
          sleep backoff_delay(attempt)
          next
        rescue Net::ReadTimeout, OpenSSL::SSL::SSLError, EOFError, SystemCallError, IOError => e
          # Anything later (read timeout, idle-keepalive reset, ...) may have
          # reached the upstream; only replay methods that are safe to repeat.
          if %w[GET HEAD].include?(method) && attempt < @retry_max_attempts
            sleep backoff_delay(attempt)
            next
          end
          raise as_sdk_error(e)
        end

        # A 401 the UPSTREAM answered and the data plane relayed (the response
        # block's X-Knox-Upstream-Status, or the ephemeral proxy's older
        # X-Knox-Destination-Status) says nothing about OUR token: it is the
        # caller's to handle, and spending the one re-mint on it would leave a
        # real revocation un-recoverable on this call. Only a KnoxCall-origin
        # 401 triggers the purge + re-mint. Mirrors node core.ts #proxySend.
        if resp.code.to_i == 401 && !reauth_done && !upstream_answered?(resp)
          purge_token
          reauth_done = true
          next
        end
        return resp
      end
    end

    # Whether a data-plane response came from the upstream (relayed) rather
    # than from KnoxCall itself.
    def upstream_answered?(resp)
      !resp["X-Knox-Upstream-Status"].nil? || !resp["X-Knox-Destination-Status"].nil?
    end

    # Validate a tenant slug before it is interpolated into a data-plane host
    # (PARITY §2). Rejects with the base bootstrap error (KnoxCall::Error, the
    # Ruby analogue of node's BootstrapError) so a hostile slug adopted from a
    # token response, /v1/account, or the credentials file never reaches the
    # wire. Returns the slug so it reads inline in the host interpolation.
    def assert_tenant_slug(tenant)
      unless tenant.is_a?(String) && TENANT_SLUG_RE.match?(tenant)
        raise Error,
              "invalid tenant slug #{tenant.inspect} — expected a DNS label; " \
              "refusing to derive a data-plane host from it"
      end
      tenant
    end

    def resolve_bootstrap
      @bootstrap ||=
        if @api_key
          AccessToken.new(access_token: @api_key)
        elsif @client_id && @client_secret
          ClientCredentials.new(client_id: @client_id, client_secret: @client_secret)
        else
          # Auto-detection found nothing usable — distinctly typed so callers
          # can branch on "not logged in — offer KnoxCall.login" (PARITY §1/§14),
          # while still a KnoxCall::Error subclass so existing rescues hold.
          raise NotAuthenticatedError,
                "No credentials: run `knoxcall login`, pass access_token/api_key or " \
                "client_id + client_secret (or bootstrap:), or set " \
                "KNOXCALL_ACCESS_TOKEN / KNOXCALL_API_KEY or " \
                "KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET"
        end
    end

    # Seed tenant/base_url from the `knoxcall login` credentials file when the
    # caller did not set them explicitly (explicit constructor/env values
    # always win). Missing/malformed file → no-op (the chain already vetted
    # presence; an explicitly passed StoredCredentials fails later, at token
    # fetch, with the re-login hint).
    def seed_from_stored_credentials(stored, base_url_explicit:)
      record = begin
        CredentialsFile.read_profile(
          CredentialsFile.resolve_path(stored.path),
          CredentialsFile.resolve_profile(stored.profile)
        )
      rescue StandardError
        nil
      end
      return unless record

      file_tenant = record["tenant"]
      @tenant ||= file_tenant if file_tenant.is_a?(String) && !file_tenant.empty?
      file_base = record["base_url"]
      if !base_url_explicit && file_base.is_a?(String) && !file_base.empty?
        @base_url = file_base.chomp("/")
      end
    end

    # Mints a token, handling the DPoP auto-upgrade (PARITY §7): in "auto"
    # mode a first refusal with invalid_dpop_proof (the oauth client record
    # requires DPoP) generates a keypair and retries the request ONCE — the
    # client operates as DPoP thereafter. Called with @token_mutex held, so
    # @dpop_key is read/written directly.
    def fetch_token
      bootstrap = resolve_bootstrap

      if bootstrap.is_a?(AccessToken)
        return { access_token: bootstrap.access_token, token_type: "Bearer",
                 expires_at: Time.now + 3600, lifetime: 3600.0,
                 tenant: nil } # pre-acquired tokens discover via /v1/account
      end

      if bootstrap.is_a?(StoredCredentials)
        # Tokens come from the `knoxcall login` credentials file. The file is
        # the cross-process cache and refresh authority (single-use rotated
        # refresh tokens, refreshed under the file lock); scope/DPoP posture
        # is whatever login negotiated. @token_mutex is held here, so the
        # in-process side of the lock is already serialized.
        return CredentialsFile.fetch_stored_token(
          path: CredentialsFile.resolve_path(bootstrap.path),
          profile: CredentialsFile.resolve_profile(bootstrap.profile),
          token_endpoint: @base_url + "/oauth/token",
          timeout: @timeout
        )
      end

      begin
        token_request(bootstrap, @dpop_key)
      rescue APIError => e
        if @dpop_mode == "auto" && @dpop_key.nil? &&
           e.body.is_a?(Hash) && e.body["error"] == "invalid_dpop_proof"
          key = DpopKeyPair.generate
          tok = token_request(bootstrap, key)
          @dpop_key = key
          return tok
        end
        raise
      end
    end

    def token_request(bootstrap, dpop_key)
      uri = URI.parse(@base_url + "/oauth/token")
      req = Net::HTTP::Post.new(uri)
      req["Content-Type"] = "application/x-www-form-urlencoded"
      req["Accept"] = "application/json"
      req["User-Agent"] = SDK_VERSION
      req["DPoP"] = dpop_key.sign("POST", uri.to_s) if dpop_key

      case bootstrap
      when ClientCredentials
        basic = ["#{bootstrap.client_id}:#{bootstrap.client_secret}"].pack("m0")
        req["Authorization"] = "Basic #{basic}"
        req.body = URI.encode_www_form(grant_type: "client_credentials")
      when OIDCTokenExchange
        req.body = URI.encode_www_form(
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
          subject_token: bootstrap.subject_token,
          audience: "knoxcall:api"
        )
      else
        raise Error, "unsupported bootstrap: #{bootstrap.class}"
      end

      resp = begin
        perform(uri, req)
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise ConnectionTimeoutError, "token request timed out: #{e.message}"
      rescue OpenSSL::SSL::SSLError, EOFError, SocketError, SystemCallError, IOError => e
        raise NetworkError, "token request failed: #{e.class}: #{e.message}"
      end

      raise KnoxCall.error_from_response(resp) if resp.code.to_i >= 400

      data = begin
        JSON.parse(resp.body.to_s)
      rescue JSON::ParserError
        nil
      end
      unless data.is_a?(Hash) && data["access_token"].is_a?(String) && !data["access_token"].empty?
        # e.g. an HTML page from an edge proxy with a 200 status
        raise TokenError, "token endpoint returned an unexpected response (status #{resp.code})"
      end
      token_type = data["token_type"].to_s.casecmp("dpop").zero? ? "DPoP" : (data["token_type"] || "Bearer")
      if token_type == "DPoP" && dpop_key.nil?
        # Sending "Authorization: DPoP <token>" without a proof 401-loops
        # forever — fail loudly instead (mode "never", or a server that
        # binds tokens without challenging first).
        raise TokenError, "server issued a DPoP-bound token but this client holds no DPoP keypair — " \
                          'construct with dpop: "auto" or "always"'
      end

      lifetime = begin
        Float(data["expires_in"] || 3600)
      rescue ArgumentError, TypeError
        3600.0
      end
      tenant = data["tenant"]
      {
        access_token: data["access_token"],
        token_type: token_type,
        expires_at: Time.now + lifetime,
        lifetime: lifetime,
        tenant: tenant.is_a?(String) && !tenant.empty? ? tenant : nil
      }
    end

    # Fresh per-request proof for a DPoP-bound token (new jti/iat + ath).
    def dpop_proof(method, url, access_token)
      key = @dpop_key
      raise TokenError, "DPoP-bound token held without a DPoP keypair — this is a bug, please report it" unless key
      key.sign(method, url, access_token: access_token)
    end

    def token_fresh?(tok)
      # For short-lived tokens a fixed 5-minute window would mean "always
      # expired", forcing a token fetch per request; never use more than
      # half the token's lifetime as the refresh-ahead window.
      ahead = tok[:lifetime] ? [REFRESH_AHEAD_SECONDS, tok[:lifetime] / 2.0].min : REFRESH_AHEAD_SECONDS
      tok[:expires_at] - Time.now > ahead
    end

    def build_request(method, uri)
      klass = METHOD_CLASSES[method.to_s.upcase] or raise ArgumentError, "Unknown method: #{method}"
      req = klass.new(uri)
      req["User-Agent"] = SDK_VERSION
      req
    end

    # Serialize a request body, defaulting Content-Type to JSON. Strings pass
    # through untouched (pre-serialized payloads with a caller Content-Type);
    # anything else is JSON-encoded with Time/Date/DateTime/BigDecimal
    # handling plus the client's json_encoder hook.
    def encode_body(body, req)
      return if body.nil?
      req["Content-Type"] = "application/json" unless req["Content-Type"]
      req.body = body.is_a?(String) ? body : JSON.generate(encode_json_value(body))
    end

    def encode_json_value(v)
      return v.to_f if defined?(BigDecimal) && v.is_a?(BigDecimal)
      case v
      when Hash then v.each_with_object({}) { |(k, val), h| h[k] = encode_json_value(val) }
      when Array then v.map { |e| encode_json_value(e) }
      when Time, DateTime then v.iso8601
      when Date then v.iso8601
      when String, Numeric, Symbol, true, false, nil then v
      else
        @json_encoder ? encode_json_value(@json_encoder.call(v)) : v
      end
    end

    def perform(uri, req, timeout: nil)
      t = timeout || @timeout
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = t
      http.read_timeout = t
      http.start { |h| h.request(req) }
    end

    def as_sdk_error(e)
      return e if e.is_a?(Error)
      if e.is_a?(Net::OpenTimeout) || e.is_a?(Net::ReadTimeout)
        ConnectionTimeoutError.new("connection timed out: #{e.message}")
      else
        NetworkError.new("network error: #{e.class}: #{e.message}")
      end
    end

    def retry_delay(err, attempt)
      # A 429's Retry-After, and a 503's (+dependency_unavailable+ — the server
      # says how long the dependency needs). Both capped: beyond the cap the
      # caller's own scheduling beats a blocked thread.
      if (err.is_a?(RateLimitError) || err.is_a?(ServerError)) && err.retry_after
        return [err.retry_after, RETRY_AFTER_CAP_SECONDS].min
      end
      backoff_delay(attempt)
    end

    def backoff_delay(attempt)
      # Half-jitter: random within [exp/2, exp] so a retry never fires
      # immediately but herds still spread out.
      exp = @retry_base_delay * (2**(attempt - 1))
      [@retry_max_delay, exp * (0.5 + rand / 2)].min
    end

    def normalize_path(path)
      path.start_with?("/") ? path : "/#{path}"
    end

    def handle_response(resp)
      raise KnoxCall.error_from_response(resp) if resp.code.to_i >= 400
      return nil if resp.body.nil? || resp.body.empty?
      begin
        JSON.parse(resp.body)
      rescue JSON::ParserError
        resp.body
      end
    end
  end
end
