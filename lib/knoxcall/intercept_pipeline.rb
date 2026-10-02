require "set"
require "uri"
require "knoxcall/errors"
require "knoxcall/warnings"
require "knoxcall/wrap_transport"
require "knoxcall/intercept_resolver"
require "knoxcall/intercept_store"
require "knoxcall/route_refusal"
require "knoxcall/egress_observations"

module KnoxCall
  # Thread-local (fiber-local) flags the route-aware seams read.
  #
  # - +routed { }+ marks a call site: with +require_context: true+ only egress
  #   performed inside the block is intercepted — you mark the CALL SITE, not
  #   the SDK.
  # - +suppressed { }+ marks the SDK's OWN traffic (the manifest poll, the
  #   route / ephemeral hop) so the process-wide Net::HTTP seam never
  #   re-intercepts it. The own-host rule already sends it direct; the flag
  #   makes that independent of URL parsing.
  module InterceptContext
    ROUTED = :knoxcall_intercept_routed
    SUPPRESS = :knoxcall_intercept_suppress

    module_function

    def routed(&block) = with_flag(ROUTED, &block)
    def routed? = Thread.current[ROUTED] ? true : false
    def suppressed(&block) = with_flag(SUPPRESS, &block)
    def suppressed? = Thread.current[SUPPRESS] ? true : false

    def with_flag(key)
      previous = Thread.current[key]
      Thread.current[key] = true
      yield
    ensure
      Thread.current[key] = previous
    end
  end

  # The ONE route-aware pipeline behind every Ruby seam — the Faraday adapter
  # ({Resources::Wrap#faraday_connection}), the Faraday middleware
  # ({Resources::Wrap#faraday_middleware}) and the opt-in Net::HTTP seam
  # ({Resources::Wrap#intercept!}) — so the decision table, the own-host
  # refusal, the kill switch and the D4 failure policy apply identically
  # (route-aware-interception-plan.md §2–§3, PARITY §21.1).
  #
  # Per request, first match wins ({InterceptResolver}): KNOXCALL_INTERCEPT=off
  # → direct · unparseable → direct · the client's own hosts and any
  # knoxcall.com host → direct · route-around rule → direct · +require_context+
  # outside +routed { }+ → direct · a manifest entry covering host + path →
  # ROUTE (the Route injects the stored secret; no provider credential travels)
  # · a listed host → EPHEMERAL · otherwise direct.
  #
  # Route mode sends through the existing {Client#call} pipeline
  # (x-knoxcall-route, the client's environment, retry + the one re-mint
  # inherited) — never a second proxy implementation. A KnoxCall-origin 401 in
  # route mode, after that re-mint, means a stale manifest or a refused
  # credential, and a KnoxCall-origin 404 route_not_found means a stale manifest
  # naming a Route that no longer resolves (PARITY §21; RouteRefusal): ONE
  # forced refresh, ONE re-decision, a resend only when the decision changed
  # (a routing refusal is answered before any upstream contact). Never a loop.
  #
  # Unavailability (D4): route mode and escrow fail CLOSED (the SDK's
  # {NetworkError}); transit may opt into going direct (+unavailable: :direct+,
  # transport-wide or per host) — the seam then performs the ORIGINAL request.
  class InterceptPipeline
    # Returned by {#send} when the seam must perform the original request
    # itself: a D4 fallback, or a re-decision to direct after a refusal.
    DIRECT = :direct

    HOOKS = %i[on_reroute on_refresh on_manifest_error on_unmatched_path on_refused on_fallback
               on_promoted on_route_around on_observation_flush].freeze

    attr_reader :store, :rules, :observer

    # @param client [KnoxCall::Client]
    # @param all_hosts [Boolean] the explicit-transport form: every request is "listed"
    # @param hosts [Array<String>, Hash{String => Hash}, nil] hosts to cover even when no Route does;
    #   a Hash carries per-host +credential:+ (escrow) / +unavailable:+ (:direct)
    # @param routes [Symbol, String] +:auto+ consults the manifest; +:off+ never polls
    # @param credential [Hash, nil] transport-wide escrow {secret:, scheme:}
    # @param route [String, nil] legacy explicit route slug (every non-direct request goes via it)
    # @param auto_switch [Boolean] legacy promoted-route memory (only consulted with routes: :off)
    # @param route_around [Array<Hash>, nil] extra route-around rules
    # @param disable_default_route_around [Boolean]
    # @param require_context [Boolean] only intercept inside +routed { }+
    # @param unavailable [Symbol] +:error+ (fail closed, default) or +:direct+ (transit only)
    # @param manifest_fetch [#call, nil] test seam: replaces the manifest call
    # @param observe_uncovered [Boolean] report uncovered egress (PARITY §21.3) — see
    #   {Resources::Wrap#faraday_connection}; +false+ or KNOXCALL_OBSERVE_UNCOVERED=off turns it off
    # @param observation_report [#call, nil] test seam: replaces the report call
    # @param hooks [Hash{Symbol => #call}] see HOOKS (+on_observation_flush+: +{accepted:, dropped:}+)
    def initialize(client:, all_hosts: false, hosts: nil, routes: :off, credential: nil, route: nil,
                   auto_switch: false, route_around: nil, disable_default_route_around: false,
                   require_context: false, unavailable: :error, manifest_fetch: nil,
                   observe_uncovered: true, observation_report: nil, **hooks)
      unknown = hooks.keys - HOOKS
      raise ArgumentError, "unknown intercept option(s): #{unknown.join(', ')}" unless unknown.empty?

      @client = client
      @all_hosts = all_hosts ? true : false
      @hosts = Set.new
      @host_options = {}
      add_hosts!(hosts)
      self.class.validate_credential!(credential, "wrap")
      @credential = credential
      @route = route.is_a?(String) && !route.empty? ? route : nil
      @auto_switch = auto_switch ? true : false
      WrapTransport.assert_route_around_rules(route_around) if route_around
      @rules = (disable_default_route_around ? [] : WrapTransport::DEFAULT_ROUTE_AROUND) + Array(route_around)
      @require_context = require_context ? true : false
      @unavailable = unavailable.to_s == "direct" ? :direct : :error
      @hooks = hooks
      @auto_switched = {}
      @unmatched_warned = Set.new
      @mutex = Mutex.new
      @store =
        if routes.to_s == "auto"
          InterceptManifestStore.new(manifest_fetch || method(:fetch_manifest),
                                     on_refresh: method(:handle_refresh),
                                     on_error: hooks[:on_manifest_error])
        end

      # Uncovered-egress observations (PARITY §21.3). ON by default (founder
      # decision 2026-09-26) for the process-wide seam and the middleware
      # (+all_hosts: false+) and for an explicit connection with
      # +routes: :auto+; +observe_uncovered: false+ or the environment turns it
      # off. An explicit connection treats every host as listed, so +:unlisted+
      # never occurs there by construction — the reporter exists so the
      # contract (and the opt-out) reads the same in every form. The report
      # rides the SDK's own credential through +request+ under the suppress
      # flag, so it is never itself intercepted.
      @observer = nil
      if observe_uncovered && !EgressObservations.disabled_by_env? && (!@all_hosts || routes.to_s == "auto")
        report = observation_report || ->(observations) { @client.wrap.report_egress_observations(observations) }
        @observer = EgressObservationReporter.new(report, on_flush: hooks[:on_observation_flush])
      end
    end

    # A malformed credential must NOT silently fall through to transit mode and
    # leak the SDK's raw key — fail loud (mirrors the Node fetch() guard).
    def self.validate_credential!(credential, where)
      return if credential.nil?

      secret = credential.is_a?(Hash) ? (credential[:secret] || credential["secret"]) : nil
      return if secret.is_a?(String) && !secret.empty?

      raise TypeError,
            "#{where} credential must be { secret: <non-empty String> } for escrow mode; " \
            "omit `credential` entirely for transit mode."
    end

    # The manifest this pipeline is deciding on, or nil (routes off / not loaded).
    def manifest = @store&.manifest

    # Load the manifest now if it is stale (the first attempt included). Never
    # raises for a manifest failure; returns the manifest or nil.
    def ready
      return nil if @store.nil?

      InterceptContext.suppressed { @store.ensure }
    end

    # Refresh the manifest now (no-op with routes off).
    def refresh
      return nil if @store.nil?

      InterceptContext.suppressed { @store.refresh("manual", force: true) }
    end

    # Stop polling and drop the manifest (and flush the uncovered-egress
    # reporter once more); the pipeline keeps working on the ephemeral path
    # for listed hosts and direct otherwise.
    def stop
      @store&.stop
      @observer&.stop
      nil
    end

    # Apply the decision table to one request (refreshing the manifest first
    # when it is stale).
    def decide(url, method)
      manifest = @store && InterceptContext.suppressed { @store.ensure }
      InterceptResolver.resolve(
        url: url, method: method,
        hosts: @all_hosts ? :all : @hosts,
        manifest: manifest,
        own_hosts: own_hosts,
        route_around: @rules,
        kill_switch: InterceptResolver.kill_switch?,
        require_context: @require_context,
        in_context: InterceptContext.routed?
      )
    end

    # A direct decision (a seam calls this before performing the original
    # request itself): fires the route-around hook, and — for +:unlisted+
    # only — records an uncovered-egress observation when the request carries
    # a credential-bearing header (PARITY §21.3). Observed AFTER the decision,
    # BEFORE the direct send; never raises into the application's request.
    def direct_decided(decision, url, method: nil, headers: nil)
      if decision.reason == :route_around
        fire(:on_route_around, url: url, host: decision.host, reason: decision.route_around_reason)
        return
      end
      return unless decision.reason == :unlisted && @observer

      begin
        obs = EgressObservations.observation_for(url, method, headers)
        @observer.record(obs) if obs
      rescue StandardError
        # best-effort: telemetry must never reach the application's request.
        nil
      end
    end

    # Send a non-direct decision through KnoxCall. Returns the
    # +Net::HTTPResponse+ from the route or ephemeral hop, or {DIRECT} when the
    # seam must perform the original request itself. +headers+ is the wrapped
    # SDK's request-header Hash (any casing); +body+ the request body (String
    # or nil — held in memory, so a resend after a routing refusal is
    # replayable by construction).
    def send(decision, url:, method:, headers:, body:)
      InterceptContext.suppressed do
        method = method.to_s.upcase
        forwardable = WrapTransport.forwardable_headers(headers)
        auth = header_value(headers, "Authorization")

        # Legacy explicit route: / auto-switch memory (pre-manifest callers):
        # every non-direct request goes via that slug with the full path.
        legacy = legacy_route_for(decision)
        if legacy
          fire(:on_reroute, host: decision.host, url: url, mode: :route, slug: legacy, reason: :explicit_route)
          return send_route(legacy, full_path(url), method, forwardable, body)
        end

        return send_route_with_refresh(decision, url, method, forwardable, auth, body) if decision.route?

        # Ephemeral.
        if decision.reason == :no_base_path_match
          key = "#{decision.host} #{first_segment(url)}"
          first = @mutex.synchronize { @unmatched_warned.add?(key) }
          fire(:on_unmatched_path, host: decision.host, url: url) if first
        end
        fire(:on_reroute, host: decision.host, url: url, mode: :ephemeral, reason: decision.reason)
        send_ephemeral(decision, url, method, forwardable, auth, body)
      end
    end

    private

    def add_hosts!(hosts)
      return if hosts.nil?

      entries = hosts.is_a?(Hash) ? hosts : Array(hosts).to_h { |h| [h, {}] }
      entries.each do |host, opts|
        assert_bare_host!(host)
        opts = (opts || {}).to_h { |k, v| [k.to_sym, v] }
        self.class.validate_credential!(opts[:credential], "intercept host #{host}")
        n = WrapTransport.normalize_host(host)
        @hosts << n
        @host_options[n] = {
          credential: opts[:credential],
          unavailable: opts[:unavailable].to_s == "direct" ? :direct : nil
        }
      end
    end

    # A listed host that is not a bare DNS hostname (a scheme/port/path slipped
    # in) could never match a parsed request host and would silently disable
    # the listing — fail loud instead.
    def assert_bare_host!(host)
      h = host.to_s.strip
      parsed = begin
        URI.parse("https://#{h}").host.to_s
      rescue URI::InvalidURIError
        ""
      end
      return unless h.empty? || WrapTransport.normalize_host(parsed) != WrapTransport.normalize_host(h)

      raise WrapSandboxMismatchError,
            "invalid intercept host #{host.inspect}: expected a bare DNS hostname (no scheme, port, or path)."
    end

    # The client's management and data-plane hosts, never intercepted.
    def own_hosts
      out = Set.new
      [@client.base_url, @client.proxy_base_url].each do |raw|
        next if raw.nil? || raw.to_s.empty?

        h = begin
          WrapTransport.normalize_host(URI.parse(raw.to_s).host)
        rescue URI::InvalidURIError
          ""
        end
        out << h unless h.empty?
      end
      out
    end

    # The store's fetch: the client's environment, and the held version as
    # If-None-Match (a 304 comes back as nil — PARITY §21.1).
    def fetch_manifest(if_none_match: nil)
      @client.wrap.intercept_manifest(environment: @client.environment, if_none_match: if_none_match)
    end

    # Warn once per entry that will be refused or is ambiguous, then forward
    # to the caller's hook.
    def handle_refresh(info)
      info[:added].each do |e|
        slug = e["slug"]
        host_base = "#{e['host']}#{e['base_path']}"
        if e["requires_clients"]
          Warnings.warn_once(
            "KNOXCALL_INTERCEPT_REQUIRES_CLIENTS:#{slug}",
            "KnoxCall route #{slug.inspect} (#{host_base}) requires a registered client; a bearer-only SDK " \
            "call will be refused (403). Register this process as a client of the route, or leave the " \
            "route out of interception."
          )
        end
        next unless e["ambiguous"]

        Warnings.warn_once(
          "KNOXCALL_INTERCEPT_AMBIGUOUS:#{host_base}",
          "KnoxCall: more than one intercept-enabled route covers #{host_base}; the lexically lowest slug " \
          "is used. Disable the others."
        )
      end
      fire(:on_refresh, **info)
    end

    def legacy_route_for(decision)
      return @route if @route
      return nil unless decision.ephemeral? && @auto_switch

      @mutex.synchronize { @auto_switched[decision.host] }
    end

    # Every route-mode reroute is marked (PARITY §21.2) — the manifest decision
    # and the legacy explicit +route:+ form alike: both are a third-party SDK's
    # call this pipeline redirected, which is what the API Log's "SDK intercept"
    # origin means.
    def send_route(slug, path, method, headers, body)
      @client.call(slug, method: method, path: path, headers: headers, body: body,
                         _origin: Client::SDK_INTERCEPT_ORIGIN)
    end

    def send_route_with_refresh(decision, url, method, headers, auth, body)
      fire(:on_reroute, host: decision.host, url: url, mode: :route, slug: decision.slug, reason: decision.reason)
      resp = send_route(decision.slug, decision.path, method, headers, body)
      return resp unless @store && route_refusal?(resp)

      @store.refresh("route_refused", force: true)
      again = decide(url, method)
      changed = !again.route? || again.slug != decision.slug || again.path != decision.path
      fire(:on_refused, host: decision.host, url: url, slug: decision.slug, status: resp.code.to_i,
                        redecided: changed ? again.mode : nil)
      return resp unless changed

      case again.mode
      when :route
        fire(:on_reroute, host: again.host, url: url, mode: :route, slug: again.slug, reason: again.reason)
        send_route(again.slug, again.path, method, headers, body)
      when :ephemeral
        fire(:on_reroute, host: again.host, url: url, mode: :ephemeral, reason: again.reason)
        send_ephemeral(again, url, method, headers, auth, body)
      else
        DIRECT
      end
    end

    def send_ephemeral(decision, url, method, headers, auth, body)
      host_opts = @host_options[decision.host] || {}
      credential = host_opts[:credential] || @credential
      opts = { method: method, body: body, headers: headers, mode: "transparent" }
      if credential
        # Escrow mode — the raw key never travels; the SDK's own key is an
        # ignored placeholder (no Test/Live assertion).
        opts[:upstream_auth_secret] = credential_field(credential, :secret)
        scheme = credential_field(credential, :scheme)
        opts[:upstream_auth_scheme] = scheme unless scheme.nil?
      else
        # Transit mode — lift the SDK's own Authorization header out-of-band.
        WrapTransport.assert_key_matches_sandbox(auth, @client.sandbox)
        opts[:upstream_authorization] = auth unless auth.nil?
      end

      begin
        resp = @client.ephemeral(url, **opts)
      rescue NetworkError => e
        # D4: fail closed by default. Going direct is honoured only for TRANSIT
        # traffic — the key is in the process there. Escrow has nothing to go
        # direct with.
        policy = host_opts[:unavailable] || @unavailable
        raise unless policy == :direct && credential.nil?

        fire(:on_fallback, host: decision.host, url: url, error: e)
        return DIRECT
      end

      # Promoted-route hint: a Route now covers this host. With a manifest the
      # hint is a signal to refresh it — the manifest is the truth. Without one
      # (legacy auto_switch), remember the slug directly.
      slug = resp["x-knox-promoted-route"]
      if slug && !decision.host.empty?
        fire(:on_promoted, host: decision.host, slug: slug)
        if @store
          @store.hint
        elsif @auto_switch
          @mutex.synchronize { @auto_switched[decision.host] = slug }
        end
      end
      resp
    end

    # A KnoxCall-origin refusal on the route data plane: a 401 with neither
    # spelling of "the upstream answered", or a 404 whose envelope error.type is
    # route_not_found (PARITY §21.1; the predicate and its cross-language
    # fixtures live in KnoxCall::RouteRefusal).
    def route_refusal?(resp)
      RouteRefusal.refusal?(status: resp.code.to_i, headers: resp.to_hash, body: resp.body)
    end

    def full_path(url)
      u = URI.parse(url)
      path = u.path.to_s.empty? ? "/" : u.path
      u.query ? "#{path}?#{u.query}" : path
    end

    def first_segment(url)
      path = begin
        URI.parse(url).path.to_s
      rescue URI::InvalidURIError
        ""
      end
      "/#{path.delete_prefix('/').split('/', 2).first}"
    end

    def header_value(headers, name)
      pair = headers.find { |k, _| k.to_s.casecmp(name).zero? }
      pair&.last
    end

    def credential_field(credential, key)
      return nil unless credential.is_a?(Hash)

      credential.key?(key) ? credential[key] : credential[key.to_s]
    end

    def fire(hook, **info)
      @hooks[hook]&.call(**info)
    end
  end
end
