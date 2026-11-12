module KnoxCall
  module Resources
    # Wrap-credential escrow (POST /v1/wrap/credentials).
    #
    # Hands a raw provider credential to KnoxCall for custody: the +value+ is
    # sent ONCE, stored under the given +name+, pinned to the supplied upstream
    # +hosts+, and never returned. The response carries only the escrowed
    # secret's metadata ({secret_id, name, provider, allowed_hosts, sandbox});
    # thereafter the credential is referenced by name and injected by the proxy.
    class Wrap
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Escrow a provider credential.
      #
      # @param provider [String] free-form provider label (e.g. "stripe")
      # @param name     [String] secret name the escrowed key is stored and
      #   later referenced under
      # @param value    [String] the raw provider credential — sent once, never
      #   returned
      # @param hosts    [Array<String>] the allowed upstream hostnames (the
      #   load-bearing pin)
      # @return [Hash] the escrowed secret's metadata: {"secret_id", "name",
      #   "provider", "allowed_hosts", "sandbox"} — the value is never echoed
      def escrow(provider:, name:, value:, hosts:)
        unwrap(@client.request("POST", "/v1/wrap/credentials",
                               body: { provider: provider, name: name, value: value, hosts: hosts }))
      end

      # Mint a base-URL gateway token bound to an escrowed credential
      # (POST /v1/wrap/tokens).
      #
      # For SDKs that expose ONLY a base-URL override and no +fetch+/transport
      # hook (Resend, Mailgun, Airtable, …): set the returned +base_url+ as the
      # wrapped SDK's base URL, and the SDK's own key becomes a placeholder —
      # KnoxCall injects the escrowed +secret+ server-side. ESCROW-ONLY: the
      # +secret+ must already be escrowed (see {#escrow}).
      #
      # The returned +token+ (also embedded in +base_url+) is a bearer
      # credential — treat it as a secret, never store or log it.
      #
      # @param secret      [String] the escrowed credential (name or id) to inject
      # @param host        [String, nil] upstream host to pin (optional when the
      #   credential allows exactly one)
      # @param ttl_seconds [Integer, nil] token TTL in seconds (omit for a
      #   non-expiring token)
      # @param label       [String, nil] human label for the token list
      # @param style       [String, nil] which +base_url+ form to return: "path"
      #   (+…/wg/<token>/<host>+) is always available; "subdomain"
      #   (+<label>.wrap.<domain>+) is only available when the operator enabled
      #   the wildcard-subdomain gateway (else the call 400s). Omit to let the
      #   server choose (subdomain when enabled, else path). NOTE: the subdomain
      #   form carries the token in the TLS SNI (plaintext on the wire) — weaker
      #   token confidentiality than the path form; prefer a short +ttl_seconds+.
      # @return [Hash] {"id", "token", "base_url", "base_url_style", "host",
      #   "secret_id", "sandbox", "expires_at"} — "base_url_style" ("path" or
      #   "subdomain") reports which form was returned
      def gateway_url(secret:, host: nil, ttl_seconds: nil, label: nil, style: nil)
        body = { secret: secret, host: host, ttl_seconds: ttl_seconds, label: label, style: style }.compact
        unwrap(@client.request("POST", "/v1/wrap/tokens", body: body))
      end

      # The intercept manifest (GET /v1/wrap/intercept-manifest): which upstream
      # hosts an intercept-enabled Route covers in this space, for one
      # environment (default: the tenant's default), and the slug to send them
      # under. What a route-aware interceptor polls; "version" doubles as the
      # ETag. Scope: routes:read.
      #
      # Conditional form: pass +if_none_match:+ (the "version" you hold — not
      # an ETag) and the SDK sends +If-None-Match: W/"<version>"+; a 304
      # returns +nil+ — keep what you hold. Everything else (auth, the one
      # re-auth on 401, retries, a 200 with a newer manifest) is exactly the
      # unconditional call, which never returns nil.
      #
      # @param environment [String, nil] the environment to resolve for
      # @param if_none_match [String, nil] the manifest version you hold
      # @return [Hash, nil] {"version", "ttl_seconds", "environment", "sandbox",
      #   "routes" => [{"host", "base_path", "slug", "route_id",
      #   "requires_clients", "allowed_methods", "updated_at"}]}; nil only for
      #   a 304 to a conditional call
      def intercept_manifest(environment: nil, if_none_match: nil)
        query = environment.nil? ? nil : { environment: environment }
        if if_none_match.nil? || if_none_match.to_s.empty?
          return unwrap(@client.request("GET", "/v1/wrap/intercept-manifest", query: query))
        end

        # Conditional form (PARITY §21.1): the held version as the server's weak
        # ETag; its 304 comes back as NOT_MODIFIED, mapped to nil.
        res = @client.request("GET", "/v1/wrap/intercept-manifest", query: query,
                              headers: { "If-None-Match" => self.class.manifest_etag(if_none_match) },
                              allow_not_modified: true)
        res.equal?(KnoxCall::Client::NOT_MODIFIED) ? nil : unwrap(res)
      end

      # The weak ETag the manifest endpoint sets for a +version+ (src/client-api/wrap.ts).
      def self.manifest_etag(version) = %(W/"#{version}")

      # Report uncovered-egress observations (POST /v1/wrap/egress-observations;
      # PARITY §21.3) — the thin typed wrapper the interceptor's reporter uses,
      # exported so an integrator can report by hand. At most 200 observations
      # per call. The body carries names, never values: a credential header's
      # NAME, the host, the first path segment, the method and counts. Scope:
      # routes:read.
      #
      # @param observations [Array<Hash>] each {host:, first_segment:, method:,
      #   header_name:, count:, first_seen:, last_seen:} (ISO-8601 UTC times)
      # @param sdk [String, nil] "<language>/<version>"; defaults to this SDK's
      # @return [Hash] {"accepted", "dropped", "reasons", "redacted"} — "redacted"
      #   (when present) counts accepted entries whose content the server
      #   reduced, by reason (e.g. "first_segment_looks_like_credential")
      def report_egress_observations(observations, sdk: nil)
        body = { sdk: sdk || "ruby/#{KnoxCall::VERSION}", observations: Array(observations) }
        unwrap(@client.request("POST", "/v1/wrap/egress-observations", body: body))
      end

      # List this space's gateway tokens (GET /v1/wrap/tokens).
      #
      # Metadata only — the token itself is never stored or returned.
      #
      # @return [Array<Hash>] each {"id", "secret_id", "host", "label",
      #   "created_at", "expires_at", "revoked_at", "last_used_at"}
      def list_gateway_tokens = unwrap(@client.request("GET", "/v1/wrap/tokens"))["tokens"]

      # Revoke a single gateway token by id (DELETE /v1/wrap/tokens/{id}).
      # Immediately invalidates it.
      #
      # @param id [String] the wrap-token id (from {#gateway_url} or
      #   {#list_gateway_tokens})
      # @return [Hash] {"id", "revoked"}
      def revoke_gateway_token(id) = unwrap(@client.request("DELETE", "/v1/wrap/tokens/#{encode(id)}"))

      # Build a +Faraday::Connection+ whose terminal adapter routes each request
      # through KnoxCall — the Ruby analogue of the Node SDK's +wrap.fetch()+
      # (PARITY §18, §21.1). Hand the returned connection to any third-party SDK
      # that accepts an injected +Faraday::Connection+; the SDK keeps its own
      # serialization, retries, idempotency keys and error types — only its HTTP
      # transport is swapped.
      #
      #   conn = knox.wrap.faraday_connection(url: "https://api.example.com")
      #   sdk  = SomeSDK.new(connection: conn)   # SDK-specific injection point
      #
      # With +routes: :auto+ the connection is ROUTE-AWARE: the intercept
      # manifest (GET /v1/wrap/intercept-manifest, the client's environment) is
      # refreshed lazily at its TTL and a request whose host + path an
      # intercept-enabled Route covers goes through that Route (the path rebased
      # under the Route's base path, query kept; the Route injects the stored
      # secret — no provider credential travels). Every other request goes
      # through the ephemeral proxy exactly as before — an explicit transport
      # treats every host as listed. The default stays +routes: :off+, so an
      # existing connection keeps its behaviour. The controls live on
      # +conn.knoxcall+ (an {InterceptPipeline}): +ready+, +refresh+,
      # +manifest+, +stop+.
      #
      # For an SDK that builds its own Faraday stack see {#faraday_middleware};
      # for the opt-in process-wide seam see {#intercept!}. An SDK that exposes
      # only a base-URL override (Resend, Mailgun, Airtable, …) uses
      # {#gateway_url}.
      #
      # Requires the OPTIONAL +faraday+ gem (KnoxCall itself has no runtime
      # dependency on it); a clear {KnoxCall::Error} is raised if it is missing.
      #
      # Credential handling mirrors the Node contract:
      # - transit mode (default): the wrapped SDK's own +Authorization+ header is
      #   lifted out-of-band into +X-Knox-Upstream-Authorization+ (never
      #   forwarded raw, never logged), with a both-must-agree Test/Live check
      #   against the client's +sandbox+ flag;
      # - escrow mode (+credential: {secret:}+, or per host via +hosts:+): the raw
      #   key stays in KnoxCall custody and only the escrowed secret name travels.
      #
      # Requests matching a route-around rule (raw-card PCI endpoints by default),
      # the client's own hosts, and — with KNOXCALL_INTERCEPT=off — everything
      # are sent to the provider DIRECTLY, untouched — pre-send decisions.
      #
      # Unavailability (decision D4): route mode and escrow fail CLOSED (a
      # +Faraday::ConnectionFailed+); +unavailable: :direct+ opts TRANSIT traffic
      # into going direct instead, firing +on_fallback+.
      #
      # NOTE: because the shared +ephemeral()+ path defaults a missing
      # +Content-Type+ to +application/json+ when a body is present, a wrapped
      # SDK that sends a body with NO Content-Type at all will have one added.
      # Every mainstream SDK (Stripe, OpenAI, …) sets its own Content-Type, which
      # is preserved verbatim, so this affects only exotic transports.
      #
      # @param url [String, nil] base URL for the connection (the provider's API
      #   base, exactly as the wrapped SDK expects)
      # @param routes [Symbol] +:auto+ consults the intercept manifest; +:off+
      #   (default) is the ephemeral-only transport
      # @param hosts [Array<String>, Hash, nil] per-host options for the ephemeral
      #   path: +{"api.resend.com" => {credential: {secret: "resend-key"}}}+
      #   (escrow) or +{unavailable: :direct}+ (transit only)
      # @param require_context [Boolean] only intercept inside {#routed}
      # @param unavailable [Symbol] +:error+ (default) or +:direct+ (transit only)
      # @param credential [Hash, nil] escrow mode {secret:, scheme:}; omit for
      #   transit mode
      # @param route [String, nil] legacy: send EVERY non-direct request via this
      #   durable route slug (x-knoxcall-route), full path, no manifest lookup
      # @param route_around [Array<Hash>, nil] extra route-around rules, each
      #   {host:, path_prefix:(optional), reason:}; matching requests go direct
      # @param disable_default_route_around [Boolean] drop the built-in raw-card
      #   (PCI) defaults
      # @param auto_switch [Boolean] legacy (routes: :off only): switch a host onto
      #   its promoted durable route after the server advertises one
      # @param direct_adapter the Faraday adapter used for direct calls (default
      #   +Faraday.default_adapter+)
      # @param on_route_around [#call, nil] {url:, host:, reason:}
      # @param on_promoted [#call, nil] {host:, slug:}
      # @param on_reroute [#call, nil] {host:, url:, mode:, slug:, reason:} before a KnoxCall send
      # @param on_refresh [#call, nil] {reason:, version:, added:, removed:} after a manifest change
      # @param on_manifest_error [#call, nil] the exception of a failed manifest refresh
      # @param on_unmatched_path [#call, nil] {host:, url:} once per host + first path segment
      # @param on_refused [#call, nil] {host:, url:, slug:, status:, redecided:} after a refusal refresh
      # @param on_fallback [#call, nil] {host:, url:, error:} when a transit request went direct
      # @param observe_uncovered [Boolean] report uncovered egress (PARITY §21.3):
      #   calls sent DIRECT because their host was +:unlisted+ while carrying a
      #   credential-bearing header — host, first path segment, method and the
      #   header NAME (never its value; never the query; never the body) — are
      #   counted and posted to +POST /v1/wrap/egress-observations+ about once a
      #   minute. ON by default for {#intercept!}, {#faraday_middleware} and
      #   +routes: :auto+; +false+ or KNOXCALL_OBSERVE_UNCOVERED=off (read when
      #   the connection is built) turns it off; nothing is reported while
      #   KNOXCALL_INTERCEPT=off. A 403 from the endpoint stops reporting for
      #   the life of the connection (warned once).
      # @param on_observation_flush [#call, nil] {accepted:, dropped:} after each accepted report
      # @param faraday_options [Hash] extra options forwarded to +Faraday.new+
      # @yield [Faraday::Connection::Builder] optional block to add
      #   request/response middleware ABOVE the KnoxCall transport — do NOT add
      #   another adapter (KnoxCall is the terminal adapter)
      # @return [Faraday::Connection] with a +knoxcall+ singleton method
      # @raise [KnoxCall::Error] if the +faraday+ gem is not installed
      # @raise [KnoxCall::WrapSandboxMismatchError] on a malformed route_around or listed host
      # @raise [TypeError] on a malformed escrow credential
      def faraday_connection(url: nil, routes: :off, hosts: nil, require_context: false, unavailable: :error,
                             credential: nil, route: nil, route_around: nil,
                             disable_default_route_around: false, auto_switch: false,
                             direct_adapter: nil, on_route_around: nil, on_promoted: nil,
                             on_reroute: nil, on_refresh: nil, on_manifest_error: nil,
                             on_unmatched_path: nil, on_refused: nil, on_fallback: nil,
                             observe_uncovered: true, on_observation_flush: nil,
                             **faraday_options, &block)
        require_faraday!
        # A typo'd hook (`on_reroutes:`) would otherwise vanish into Faraday's
        # options and never fire — fail loud instead.
        typos = faraday_options.keys.select { |k| k.to_s.start_with?("on_") }
        raise ArgumentError, "unknown intercept hook(s): #{typos.join(', ')}" unless typos.empty?

        pipeline = KnoxCall::InterceptPipeline.new(
          client: @client, all_hosts: true, hosts: hosts, routes: routes, credential: credential,
          route: route, auto_switch: auto_switch, route_around: route_around,
          disable_default_route_around: disable_default_route_around,
          require_context: require_context, unavailable: unavailable,
          on_route_around: on_route_around, on_promoted: on_promoted, on_reroute: on_reroute,
          on_refresh: on_refresh, on_manifest_error: on_manifest_error,
          on_unmatched_path: on_unmatched_path, on_refused: on_refused, on_fallback: on_fallback,
          observe_uncovered: observe_uncovered, on_observation_flush: on_observation_flush
        )

        conn = Faraday.new(url: url, **faraday_options) do |f|
          # Caller middleware sits ABOVE our transport; KnoxCall is terminal.
          block&.call(f)
          f.adapter(KnoxCall::Resources::Wrap::FaradayAdapter, pipeline: pipeline, direct_adapter: direct_adapter)
        end
        conn.define_singleton_method(:knoxcall) { pipeline }
        conn
      end

      # A Faraday MIDDLEWARE for a stack an SDK builds itself and lets you add
      # middleware to. Returns the +[klass, options]+ pair Faraday's builder
      # takes; a request a Route covers, or whose host is listed, is answered
      # from KnoxCall without reaching the SDK's own adapter — everything else
      # continues down the stack untouched.
      #
      #   conn.builder.insert_before(Faraday::Adapter, *knox.wrap.faraday_middleware(hosts: ["api.resend.com"]))
      #   # or, building a stack yourself:
      #   Faraday.new { |f| f.use(*knox.wrap.faraday_middleware); f.adapter :net_http }
      #
      # Route discovery is ON by default here (+routes: :auto+) — only listed
      # or route-covered hosts are touched (decision D2). The pipeline (ready /
      # refresh / manifest / stop) is +options[:pipeline]+ of the returned pair.
      #
      # @param hosts [Array<String>, Hash, nil] hosts to cover even when no Route does
      # @param routes [Symbol] +:auto+ (default) or +:off+
      # @param opts [Hash] the remaining {#faraday_connection} options except
      #   +url:+, +direct_adapter:+ and the Faraday options
      # @return [Array(Class, Hash)] +[FaradayMiddleware, {pipeline: …}]+
      def faraday_middleware(hosts: nil, routes: :auto, **opts)
        require_faraday!
        pipeline = KnoxCall::InterceptPipeline.new(client: @client, all_hosts: false, hosts: hosts, routes: routes, **opts)
        [KnoxCall::Resources::Wrap::FaradayMiddleware, { pipeline: pipeline }]
      end

      # Install the opt-in, EXPERIMENTAL process-wide seam (founder decision D7,
      # 2026-09-25): +Net::HTTP#request+ is prepended so an UNTOUCHED
      # third-party SDK on Net::HTTP — Faraday's default adapter, +rest-client+,
      # +httparty+, raw Net::HTTP — has its calls sent through the Route that
      # covers them, through the ephemeral proxy for hosts listed here that no
      # Route covers, and left alone otherwise (decision D2: never "all egress").
      # Typhoeus / Curb / +http.rb+ have their own socket layer and are NOT
      # reached — point those SDKs at {#gateway_url}.
      #
      #   stop = knox.wrap.intercept!(hosts: ["api.resend.com"])
      #   stop.ready                              # first manifest loaded
      #   Net::HTTP.get(URI("https://api.hubapi.com/crm/v3/objects/contacts")) # via the covering Route
      #   stop.uninstall
      #
      # One handle per process (a second call raises {KnoxCall::Error});
      # +uninstall+ restores pass-through. This is a convenience, not a security
      # boundary: it is a process global and composes with other Net::HTTP
      # patchers in install order. Route mode is the custody path — the key
      # never enters your process.
      #
      # @param hosts [Array<String>, Hash, nil] as {#faraday_connection}
      # @param stacks [Array<Symbol>] which seams to install; only +:net_http+ exists
      # @param routes [Symbol] +:auto+ (default) or +:off+ (listed hosts, ephemeral only)
      # @param require_context [Boolean] only intercept inside {#routed}
      # @param opts [Hash] +unavailable:+, +credential:+, +route_around:+,
      #   +disable_default_route_around:+ and the +on_*+ hooks of {#faraday_connection}
      # @return [KnoxCall::InterceptHandle]
      def intercept!(hosts: nil, stacks: [:net_http], routes: :auto, require_context: false, **opts)
        unknown = Array(stacks).map(&:to_sym) - [:net_http]
        raise ArgumentError, "unknown intercept stack(s): #{unknown.join(', ')} (only :net_http exists)" unless unknown.empty?

        require "knoxcall/intercept_patch"
        pipeline = KnoxCall::InterceptPipeline.new(client: @client, all_hosts: false, hosts: hosts, routes: routes,
                                                    require_context: require_context, **opts)
        KnoxCall::Intercept.install(pipeline)
      end

      # Run the block in a "routed" scope. With +require_context: true+, only
      # egress performed inside {#routed} (on this thread) is intercepted — you
      # mark the CALL SITE, not the SDK.
      def routed(&block) = KnoxCall::InterceptContext.routed(&block)

      private

      # Lazily load the optional faraday gem (and the adapter + middleware, which
      # reference Faraday at load time). Raises a clear, actionable error when it
      # is not installed rather than a bare LoadError.
      def require_faraday!
        require "faraday"
        require "knoxcall/wrap_faraday_adapter"
        require "knoxcall/wrap_faraday_middleware"
      rescue LoadError => e
        raise KnoxCall::Error,
              "wrap.faraday_connection requires the optional `faraday` gem, which is not installed. " \
              "Add `gem \"faraday\"` to your Gemfile — KnoxCall has no runtime dependency on it. For " \
              "third-party SDKs that accept only a base-URL override (no injected Faraday connection), " \
              "use wrap.gateway_url instead. (#{e.class}: #{e.message})"
      end
    end
  end
end
