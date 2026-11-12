require "uri"
require "set"
require "knoxcall/wrap_transport"

module KnoxCall
  # The route-aware interception decision table — pure, no I/O
  # (docs/internal/sdk-wrapping/route-aware-interception-plan.md §2.2, PARITY
  # §21.1). One request in, one decision out: send it DIRECT (untouched),
  # through a ROUTE (the manifest says an intercept-enabled Route covers this
  # host + path; the Route injects the stored secret), or through the EPHEMERAL
  # proxy (the caller listed the host, no Route covers it; the SDK's own
  # credential is lifted out-of-band). The order of the rules is the feature.
  #
  # Every SDK's resolver passes the SAME fixtures — sdk/fixtures/intercept-
  # resolver.json (spec/intercept_resolver_spec.rb runs them here) — so this is
  # the Ruby copy of a contract whose reference is the Node SDK's
  # src/intercept-resolver.ts, not a private heuristic.
  module InterceptResolver
    MODES = %i[direct route ephemeral].freeze
    REASONS = %i[kill_switch unparseable own_host route_around outside_context
                 manifest no_base_path_match no_route unlisted].freeze

    # The resolver's answer for one request. +slug+ / +path+ / +entry+ are set
    # in route mode only; +route_around_reason+ for a route-around match.
    Decision = Struct.new(:mode, :reason, :host, :slug, :path, :entry, :route_around_reason,
                          keyword_init: true) do
      def direct? = mode == :direct
      def route? = mode == :route
      def ephemeral? = mode == :ephemeral
    end

    module_function

    # KNOXCALL_INTERCEPT=off (or 0 / false): every interceptor and route-aware
    # transport becomes pass-through, per request, with no deploy.
    def kill_switch?
      %w[off 0 false].include?(ENV.fetch("KNOXCALL_INTERCEPT", "").strip.downcase)
    end

    # KnoxCall's own domains are never intercepted, whatever a manifest or a
    # host list says (anti-recursion).
    def platform_host?(host)
      host == "knoxcall.com" || host.end_with?(".knoxcall.com")
    end

    # Read a manifest-entry field tolerating string and symbol keys (the parsed
    # manifest is string-keyed; a hand-built one may not be).
    def entry_value(entry, key)
      return nil unless entry.is_a?(Hash)

      entry.key?(key.to_s) ? entry[key.to_s] : entry[key.to_sym]
    end

    # The request path with the route's base prefix removed (leading slash
    # kept), or +nil+ when the request is not under the base. "/crm/v3" covers
    # "/crm/v3" and "/crm/v3/x", never "/crm/v30" — the boundary is a path
    # segment. Mirrors the server's rebasePath (src/lib/route-target-host.ts).
    def rebase_path(request_path, base_path)
      req_path = request_path.to_s.empty? ? "/" : request_path.to_s
      if base_path.nil? || base_path == "/" || base_path == ""
        return req_path.start_with?("/") ? req_path : "/#{req_path}"
      end
      return "/" if req_path == base_path
      return nil unless req_path.start_with?("#{base_path}/")

      rest = req_path[base_path.length..]
      rest.empty? ? "/" : rest
    end

    # Manifest entries for a host in the order the server sorts them — longest
    # base_path first, then base_path, then slug — so the first entry whose
    # base covers the path is the longest-prefix, lowest-slug match.
    def entries_for_host(manifest, host)
      return [] if manifest.nil?

      routes = entry_value(manifest, :routes) || []
      routes.select { |e| WrapTransport.normalize_host(entry_value(e, :host)) == host }
            .sort_by { |e| bp = entry_value(e, :base_path).to_s; [-bp.length, bp, entry_value(e, :slug).to_s] }
    end

    # Apply the decision table. First match wins.
    #
    # @param url [String] the request URL
    # @param method [String] the HTTP method (carried for hooks; not a rule input today)
    # @param hosts [Set<String>, :all] the caller's explicit host list (normalised),
    #   or +:all+ for the explicit-transport form where every request is listed
    # @param manifest [Hash, nil] the intercept manifest ({"routes" => [...]})
    # @param own_hosts [Set<String>] the client's own hosts (management + data plane)
    # @param route_around [Array<Hash>] route-around rules
    # @param kill_switch [Boolean]
    # @param require_context [Boolean] only intercept inside +routed { }+
    # @param in_context [Boolean] whether this request is inside +routed { }+
    # @return [Decision]
    def resolve(url:, method:, hosts:, manifest:, own_hosts:, route_around:,
                kill_switch: false, require_context: false, in_context: false)
      _ = method
      return Decision.new(mode: :direct, reason: :kill_switch, host: "") if kill_switch

      u = begin
        URI.parse(url.to_s)
      rescue URI::InvalidURIError
        nil
      end
      unless u && %w[http https].include?(u.scheme.to_s.downcase)
        return Decision.new(mode: :direct, reason: :unparseable, host: "")
      end
      host = WrapTransport.normalize_host(u.host)
      return Decision.new(mode: :direct, reason: :unparseable, host: "") if host.empty?

      if platform_host?(host) || own_hosts.include?(host)
        return Decision.new(mode: :direct, reason: :own_host, host: host)
      end

      around = WrapTransport.match_route_around(url.to_s, route_around)
      if around
        return Decision.new(mode: :direct, reason: :route_around, host: host,
                            route_around_reason: WrapTransport.rule_value(around, :reason))
      end

      return Decision.new(mode: :direct, reason: :outside_context, host: host) if require_context && !in_context

      entries = entries_for_host(manifest, host)
      entries.each do |entry|
        rebased = rebase_path(u.path, entry_value(entry, :base_path))
        next if rebased.nil?

        path = u.query ? "#{rebased}?#{u.query}" : rebased
        return Decision.new(mode: :route, reason: :manifest, host: host,
                            slug: entry_value(entry, :slug), path: path, entry: entry)
      end

      listed = hosts == :all || hosts.include?(host)
      if listed
        return Decision.new(mode: :ephemeral, reason: entries.empty? ? :no_route : :no_base_path_match, host: host)
      end

      Decision.new(mode: :direct, reason: :unlisted, host: host)
    end
  end
end
